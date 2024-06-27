use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{decode, Algorithm::HS256, DecodingKey, Validation};
use log::error;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::{Deserialize, Serialize};

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(RBACRoot { config: None })
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
        match &self.config {
            Some(config) => match &config.source {
                DataSource::Header { header_name } => {
                    self.handle_header_source(header_name, config)
                }
                DataSource::Jwt => self.handle_jwt_source(config),
            },
            None => self.access_forbidden(),
        }
    }
}

impl RBACRoot {
    fn handle_header_source(&self, header_name: &str, config: &Config) -> Action {
        let headers = self.get_http_request_headers();
        let maybe_enc_header_val = match get_header_val(header_name, &headers) {
            Some(h) => h,
            None => return self.access_forbidden(),
        };

        let header_val = match decode_base64(&maybe_enc_header_val) {
            Ok(val) => val,
            Err(_) => maybe_enc_header_val, // Not base64 encoded
        };

        let entries: Vec<String> = match serde_json::from_str(&header_val) {
            Ok(e) => e,
            Err(e) => {
                error!("JSON deserialization error: {}", e);
                return self.access_forbidden();
            }
        };

        if acl_match(config.match_all, &config.acl, &entries) {
            Action::Continue
        } else {
            self.access_forbidden()
        }
    }

    fn handle_jwt_source(&self, config: &Config) -> Action {
        let headers = self.get_http_request_headers();
        let auth_header = match get_header_val("authorization", &headers) {
            Some(h) => h,
            None => return self.access_forbidden(),
        };

        let key = DecodingKey::from_secret(&[]);
        let mut validation = Validation::new(HS256);
        validation.insecure_disable_signature_validation();

        let roles = match decode::<Claims>(&auth_header, &key, &validation) {
            Ok(c) => c.claims.roles.unwrap_or_else(Vec::new),
            Err(e) => {
                error!("JWT deserialization error: {}", e);
                return self.access_forbidden();
            }
        };

        if acl_match(config.match_all, &config.acl, &roles) {
            Action::Continue
        } else {
            self.access_forbidden()
        }
    }

    fn access_forbidden(&self) -> Action {
        self.send_http_response(403, vec![], Some(b"Access forbidden.\n"));
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
            let config: Config = match parse_config(&json_string) {
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

fn get_header_val(key: &str, headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.clone())
}

fn decode_base64(encoded: &str) -> Result<String, base64::DecodeError> {
    general_purpose::STANDARD
        .decode(encoded)
        .map(|decoded| String::from_utf8(decoded).unwrap_or_default())
}

fn acl_match<T: Eq>(match_all: bool, acl: &[T], entities: &[T]) -> bool {
    if match_all {
        acl.iter().all(|a| entities.contains(a))
    } else {
        entities.iter().any(|e| acl.contains(e))
    }
}

fn parse_config(config_string: &str) -> Result<Config, serde_json::Error> {
    serde_json::from_str(config_string)
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
        let config = r#"
        {
            "acl": ["foo", "baa"],
            "source": {
                "type": "Header",
                "header_name": "Authorization"
            },
            "match_all": true
        }"#;

        let config: Config = parse_config(config).unwrap();
        assert!(config.match_all);
    }

    #[test]
    fn parse_jwt_config() {
        let config = r#"
        {
            "acl": ["foo", "baa"],
            "source": {
                "type": "Jwt"
            },
            "match_all": true
        }"#;

        let config: Config = parse_config(config).unwrap();
        assert!(config.match_all);
    }
}
