# Envoy WASM RBAC Filter
This repository contains an envoy wasm filter that is able to test a provided ACL list against a specified header field or JWT. The http header value can be a raw or base64 encoded json string.
In case of JWT, the token is parsed from the <i>Authorization</i> HTTP header and the __signature validation is skipped__. Here the role claim is used and needs to contain the array of the roles.

If any parsing of the headers or jwt failes or the ACL check fails, a HTTP 403 status is returned.
If the ACL check succeeds, the request is continued to the upstream target.

## Build
```bash
just build
```

## Test
```bash
just test
```

## Filter Configuration
To pass configuration to the wasm filter add the following section to your envoy wasm filter config:

```yaml
configuration:
  "@type": "type.googleapis.com/google.protobuf.StringValue"
  value: '{ "acl": ["foo", "baa"], "source": { "type" : "Header", "header_name": "x-role-list" }, "match_all": true }'
```

### Configuration Format
The configuration format is a simple JSON object:

HTTP Header:
```json
{
    "acl": ["String"],
    "source" : {
        "type": "Header",
        "header_name": "HEADER_NAME"
    },
    "match_all": true
}
```

JWT:
```json
{
    "acl": ["String"],
    "source" : {
        "type": "Jwt"
    },
    "match_all": true
}
```

The <i>acl</i> field contains the list of roles to be checked agains.
The <i>match_all</i> field is a boolean that controls if all roles in the acl list need to be present in the data source.

## Try it out
First build the filter

```bash
just build
```

then start the envoy proxy with docker:

```bash
docker-compose up
```

Send requests with curl:

```bash
curl -H "x-role-list: [\"foo\", \"baa\"]" localhost:10000
RBAC validation ok
```

```bash
curl -H "x-role-list: [\"baa\"]" localhost:10000
Access forbidden.
```

```bash
export LIST=$(echo '["foo", "baa"]' | base64)
curl -H "x-role-list: $LIST" localhost:10000
RBAC validation ok
```