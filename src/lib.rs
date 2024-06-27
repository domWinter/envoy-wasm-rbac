use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::decode;
use jsonwebtoken::{Algorithm::HS256, DecodingKey, Validation};
use log::error;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::{Deserialize, Serialize};

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(RBACRoot {
            config: None,
        })
    });
}}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    roles: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
enum DataSource {
    Header { header_name: String },
    Jwt,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
    acl: Vec<String>,
    match_all: bool,
    source: DataSource,
}

struct RBACRoot {
    config: Option<Config>,
}

impl Context for RBACRoot {}
impl HttpContext for RBACRoot {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        if let Some(config) = &self.config {
            match &config.source {
                DataSource::Header { header_name } => {
                    let maybe_enc_header_val =
                        match get_header_val(header_name, &self.get_http_request_headers()) {
                            Some(h) => h,
                            None => {
                                self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
                                return Action::Continue;
                            }
                        };

                    // Test if base64 encoded
                    let header_val = match general_purpose::STANDARD.decode(&maybe_enc_header_val) {
                        Ok(decoded) => match String::from_utf8(decoded) {
                            Ok(s) => s,
                            Err(e) => {
                                error!("No valid utf8: {}", e);
                                self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
                                return Action::Continue;
                            }
                        },
                        Err(_) => maybe_enc_header_val, //No base64
                    };

                    let entries: Vec<String> = match serde_json::from_str(&header_val) {
                        Ok(e) => e,
                        Err(e) => {
                            error!("Json deserialisation error: {}", e);
                            self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
                            return Action::Continue;
                        }
                    };

                    if acl_match(config.match_all, &config.acl, &entries) {
                        return Action::Continue;
                    }

                    self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
                    return Action::Continue;
                }
                DataSource::Jwt {} => {
                    let auth_header =
                        match get_header_val("authorization", &self.get_http_request_headers()) {
                            Some(h) => h,
                            None => {
                                self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
                                return Action::Continue;
                            }
                        };

                    let key = DecodingKey::from_secret(&[]);
                    let mut validation = Validation::new(HS256);
                    validation.insecure_disable_signature_validation();

                    let roles = match decode::<Claims>(&auth_header, &key, &validation) {
                        Ok(c) => match c.claims.roles {
                            Some(roles) => roles,
                            None => {
                                self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
                                return Action::Continue;
                            }
                        },
                        Err(e) => {
                            error!("JWT deserialisation error: {}", e);
                            self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
                            return Action::Continue;
                        }
                    };

                    if acl_match(config.match_all, &config.acl, &roles) {
                        return Action::Continue;
                    }

                    self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
                    return Action::Continue;
                }
            }
        } else {
            self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
        }

        Action::Continue
    }
}

impl RootContext for RBACRoot {
    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            let json_string = match String::from_utf8(config_bytes) {
                Ok(s) => s,
                Err(err) => {
                    error!("{}", err);
                    return false;
                }
            };
            let config: Config = match serde_json::from_str(&json_string) {
                Ok(c) => c,
                Err(err) => {
                    error!("{}", err);
                    return false;
                }
            };
            self.config = Some(config);
        }
        true
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(RBACRoot {
            config: self.config.clone(),
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

fn get_header_val(key: &str, headers: &Vec<(String, String)>) -> Option<String> {
    let header_vals: Vec<String> = headers
        .into_iter()
        .filter(|h| &h.0.to_lowercase() == &key.to_lowercase())
        .map(|kv| kv.1.clone())
        .collect();

    if header_vals.len() != 1 {
        return None;
    }

    Some(header_vals[0].clone())
}

fn acl_match<T: Eq>(match_all: bool, acl: &Vec<T>, entities: &Vec<T>) -> bool {
    if match_all {
        return acl.iter().all(|a| entities.contains(a));
    }
    entities.iter().find(|e| acl.contains(e)).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_extract_existing_header() {
        let headers = vec![
            ("foo".to_owned(), "baa".to_owned()),
            ("Authorization".to_owned(), "test".to_owned()),
        ];
        assert_eq!(
            get_header_val("Authorization", &headers),
            Some("test".to_owned())
        );
        assert_eq!(get_header_val("foo", &headers), Some("baa".to_owned()));
        assert!(get_header_val("baa", &headers).is_none())
    }

    #[test]
    fn acl_match_single() {
        let acl = vec!["Admin", "Test", "Foo"];
        let match_all = false;
        assert!(acl_match(match_all, &acl, &vec!["Admin", "Test"]));
        assert!(acl_match(match_all, &acl, &vec!["Admin", "Test", "Foo"]));
        assert!(acl_match(match_all, &acl, &vec!["Admin"]));
        assert!(acl_match(match_all, &acl, &vec!["Foo"]));
        assert!(!acl_match(match_all, &acl, &vec!["Baa"]));
        assert!(!acl_match(match_all, &acl, &vec![]));
    }

    #[test]
    fn acl_match_all() {
        let acl = vec!["Admin", "Test", "Foo"];
        let match_all = true;
        assert!(!acl_match(match_all, &acl, &vec!["Admin", "Test"]));
        assert!(acl_match(match_all, &acl, &vec!["Admin", "Test", "Foo"]));
        assert!(!acl_match(match_all, &acl, &vec!["Admin"]));
        assert!(!acl_match(match_all, &acl, &vec!["Foo"]));
        assert!(!acl_match(match_all, &acl, &vec!["Baa"]));
        assert!(!acl_match(match_all, &acl, &vec![]));
    }

    #[test]
    fn parse_header_config() {
        let config = "{ \"acl\": [\"foo\", \"baa\"], \"source\": { \"type\": \"Header\", \"header_name\": \"Authorization\"}, \"match_all\": true }";

        let config: Config = serde_json::from_str(&config).unwrap();
        assert!(config.match_all);
    }

    #[test]
    fn parse_jwt_config() {
        let config = "{ \"acl\": [\"foo\", \"baa\"], \"source\": { \"type\": \"Jwt\"}, \"match_all\": true }";

        let config: Config = serde_json::from_str(&config).unwrap();
        assert!(config.match_all);
    }
}
