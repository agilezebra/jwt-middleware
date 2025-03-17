[![Build](https://github.com/agilezebra/jwt-middleware/actions/workflows/build.yml/badge.svg)](https://github.com/agilezebra/jwt-middleware/actions/workflows/build.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=agilezebra_jwt-middleware&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=agilezebra_jwt-middleware)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=agilezebra_jwt-middleware&metric=coverage)](https://sonarcloud.io/summary/new_code?id=agilezebra_jwt-middleware)

# Dynamic JWT Validation Middleware

This is a middleware plugin for [Traefik](https://github.com/containous/traefik) with the following features:
* Validation of JSON Web Tokens in cookies, headers, and/or query string parameters for access control.
* Dynamic lookup of public keys from the well-known OpenID configuration of whitelisted issuers.
* Flexible claim checks, including optional wildcards and Go template interpolation.
* Configurable HTTP redirects for unauthorized and forbidden calls for interactive requests.
* gRPC compatibility.

## Configuration

1a. Add the plugin to traefik, either in your static traefik config file:
```yaml
experimental:
  plugins:
    jwt:
      moduleName: github.com/agilezebra/jwt-middleware
      version: v1.2.12
```
1b. or with command-line options:

```yaml
command:
  ...
  - "--experimental.plugins.jwt.modulename=github.com/agilezebra/jwt-middleware"
  - "--experimental.plugins.jwt.version=v1.2.12"
```

2) Configure and activate the plugin as a middleware in your dynamic traefik config:
```yaml
http:
  middlewares:
    secure-api:
      plugin:
        jwt:
          issuers:
            - https://auth.example.com
          require:
            aud: test.example.com
```

3) use the middleware in services via docker-compose labels
```yaml
  labels:
    - "traefik.http.routers.my-service.middlewares=secure-api@file"
```

### Options

The plugin supports the following configuration options.

Name | Description
---- | ----
`issuers` | A list of trusted issuers to fetch keys (JWKs) from. Keys will be prefetched from these issuers on startup (unless `skipPrefetch` is set). If an inbound request presents a token signed with a key (`kid`) that is not known and its `iss` claim matches one of the `issuers`, the plugin will refresh the keys for that issuer. On each fetch, any keys previously fetched from the issuer that are no longer retrieved will be removed from the plugin's cache. Keys are fully reference counted by `kid`: if they same `kid` is present from another provider (or from `secrets` below) it will not be removed from the cache until no longer referenced. fnmatch-style wildcards are supported for `issuers` to accommodate some multitenancy scenarios (e.g. `https://*.example.com`). It is not recommended to use wildcard `issuers` unless you understand the implication that any webserver on your domain could be used to spoof a JWK endpoint and you have full confidence in what is running on all servers within the domain in question. 
`secret` | A shared HMAC secret or a fixed public key to use for signature validation. A fixed secret may be used in conjunction with `issuers` to combine static and dynamic keys. This can be useful when transitioning from earlier systems or for machine-to-machine tokens signed with internal keys. Note that if a dynamic key is not matched for a presented token's key, but a static secret is configured, the static secret will be tried as a fallback key. If this secret is not of the correct type for the presented key, an error such as `token signature is invalid: key is of invalid type` will be returned to the user, which may be confusing. 
`secrets` | A map of kid -> secret. As `secret` above, these may be used in combination with `issuers`. Any secrets provided here will be preloaded into the plugin's cache. Any presented tokens with matching `kid`s will therefore not need have the key fetched from the issuer. This mechanism is preferred over a single anonymous `secret` when a `kid` is used, as it avoids the fallback type message described above.
`skipPrefetch` | Don't prefetch keys from `issuers`. This is useful if all the expected secrets are provided in `secrets`, especially in situations where traefik or its services are frequently restarted, to save from hitting the issuer JWKS endpoint unnecessarily.
`delayPrefetch` | Delay prefetching from keys from `issuers` by the given duration (expressed in `time.ParseDuration` format - e.g. "300ms", "5s"). This is particularly useful if your openid server is behind the very traefik service that is loading the plugin and you need to give it time to be ready for your request. This has no effect if `skipPrefetch` is set.
`refreshKeysInterval` | Arbitrarily refresh all keys from all `issuers` in a background thread every given duration (after any prefetch).
`require` | A map of zero or more claims that must all be present and match against one or more values. If no claims are specified in `require`, all tokens that are validly signed by the trusted issuers or secrets will pass. If more than one claim is specified, each is required (i.e. an AND relationship exists for all the specified claims). For each claim, multiple values may be specified and the claim will be valid if any matches (i.e. an OR relationship exists for required values within a claim). fnmatch-style wildcards are optionally supported for claims in issued JWTs. If you do not wish to support wildcard claims, simply do not put such wildcards into the JWTs that you issue. See below for examples and the variables available with template interpolation.
`headerMap` | A map in the form of header -> claim. Headers will be added (or overwritten) to the forwarded HTTP request from the claim values in the token. If the claim is not present, no action for that value is taken (and any existing header will remain unchanged).
`cookieName` | Name of the cookie to retrieve the token from if present. Default: `Authorization`. If token retrieval from cookies must be disabled for some reason, set to an empty string.  If `forwardAuth` is `false`, the cookie will be removed before forwarding to the backend.
`headerName` | Name of the Header to retrieve the token from if present. Default: `Authorization`. If token retrieval from headers must be disabled for some reason, set to an empty string. Tokens are supported either with or without a `Bearer ` prefix. If `forwardAuth` is `false`, the header will be removed before forwarding to the backend.
`parameterName` | Name of the query string parameter to retrieve the token from if present. Default: disabled. If `forwardAuth` is `false`, the query string parameter will be removed before forwarding to the backend.
`redirectUnauthorized` | URL to redirect Unauthorized (401) claims to instead of returning a 401 status code. This is intended for interactive requests where the user should be redirected to login and then returned to the page that access was attempted from. Go template interpolation may be used to construct a `return_to` or similar parameter for the redirection. See examples and template variables below. 
`redirectForbidden` | URL to redirect Forbidden (403) claims to instead of returning a 403 status code. As above, this is intended for interactive requests and the same template interpolation applies. This is most useful to redirect a user to explain that they do not have access to the resource, even though they are authenticated. Such pages may, for example, offer explanations of how access may be obtained or may offer to allow the user to try using a different identity. If `redirectUnauthorized` is given but not `redirectForbidden` the URL for `redirectUnauthorized` will be used, rather than returning an HTTP status to an interactive session.
`freshness` | Integer value in seconds to consider a token as "fresh" based on its `iat` claim, if present. If a token is not within this freshness window, the plugin allows that a user may have recently had new permissions and thus new claims granted since last logging in, and will issue a 401 in place of a 403 (as well as redirecting interactive sessions as if Unauthorized). Once a user has logged in again, their token will be within the freshness window and a definitive 403 can be returned or not on subsequent attempts. Default 3600 = 1 hour. Set freshness = 0 to disable.
`forwardToken` | Boolean indicating whether the token should be forwarded to the backend. Default true. If multiple tokens are present in different locations (e.g. cookie and header) and forwarding is false, only the token used will be removed. 
`optional` | Validate tokens according to the normal rules but don't require that a token be present. If specific claim requirements are specified in `require` but with `optional` set to `true` and a token is not present, access will be permitted even though the requirements are obviously not met, which may not be what you want or expect. In this case, no headers will be set from claims (as there aren't any). This is quite a niche case but is intended for use on endpoints that support both authorized and anonymous access and you want JWTs verified if present.
`insecureSkipVerify` | A list of issuers' domains for which TLS certificates should not be verified (i.e. use `InsecureSkipVerify: true`). Only the hostname/domain should be specified (i.e. no scheme or trailing slash). Applies to both the openid-configuration and jwks calls.
`rootCAs` | One or more additional root certificate authorities, each expressed either inline in PEM format, or as a path to a file, to be combined with the system cert pool when verifying server certificates.
`infoToStdout` | traefik does not yet have support for plugins to use the logger so, by default, all messages are logged using `log.Printf`, which will send messages from the plugin out as if they were logged at `ERROR` level. This may be irritating for those that don't like to see non-error messages show up as if they are errors. There is a workaround available in that the plugin can send messages to STDOUT and traefik will log these as if they were logged at `DEBUG` level. Setting `infoToStdout` to `true` will send all non-error info messages to STDOUT and these will appear in logs at `DEBUG` level. These will obviously only appear if you set your traefik log level to `DEBUG` (which may actually be more irritating if you don't want the spew that this creates, so this option is not enabled by default). Note also that this workaround does not appear to be working correctly in traefik v2 and in this case you may not see info messages at all if you enable this.

### Template Interpolation
The following per-request variables and functions are available for Go template interpolation:

Name | Description
----|----
`{{.URL}}` | Full request URL including scheme and any query string parameters.
`{{.Method}}` | HTTP method of request (uppercase).
`{{.Scheme}}` | https or http.
`{{.Host}}` | Host name only, without scheme, including port if any.
`{{.Path}}` | Path and any query string parameters.
`{{URLQueryEscape}}` | Function: escape a variable suitable for use in a URL query (uses `url.QueryEscape`), such as `{{.URL}}` for use as a `return_to` paramater in an HTTP redirect.
`{{HTMLEscape}}` | Function: escape a variable using HTML escapes (uses `html.EscapeString`).

These variables are useful with dynamic claim requirements, particularly in multitenancy scenarios. However, if interpolating `Host` as a requirement, care must be taken to ensure that the service can only be reached through that hostname and not directly by some public IP. I.e. routing should be well-controlled, such as behind an API gateway, proxy or other ingress selecting on `Host`, or where all traefik rules are guaranteed to match using `Host`. Otherwise, it would be easy to spoof a different `Host` by fabricating a DNS record for that IP externally; a static requirement should be used instead in such an architecture.

Additionally, all environment variables are accessible with template interpolation, which makes programmatically setting a static value in the traefik dynamic config file easier.
Note that the per-request variables will overwrite traefiks view of an environment variable with the same name, so any shadowed enviorment variables need to be renamed appropriately.`


### Claim Matching

The following config snippet / JWT example pairs illustrate requirements and claims that satisfy them:
#### Simple
```yaml
require:
  aud: "customer.example.com"
```

```json
{
  "iss": "auth.example.com",
  "aud": "customer.example.com"
}
```

#### Dynamic Requirement
E.g. for requiring that a token's audience matches the domain being accessed (see notes in [Template Interpolation](###Template-Interpolation) above for caution on how and when this is safe to use dynamically like this)

Will succeed when called on https://customer.example.com/example but fail on https://other.example.com/example
Note that it is necessary to escape the Go template to prevent traefik from attempting to interpret it.
```yaml
require:
  aud: "{{`{{.Host}}`}}"
```

```json
{
  "iss": "auth.example.com",
  "aud": "customer.example.com"
}
```

#### Wildcard Claim
```yaml
require:
  aud: "customer.example.com"
```

```json
{
  "iss": "auth.example.com",
  "aud": "*.example.com"
}
```
Note that the wildcard claim is granted to the _user_ in their JWT, not asked for in the requirements. I.e. you are granting a key that can open multiple locks rather than creating a lock that accepts multiple keys. If you don't want to support these optional wildcards, simply do not issue such JWTs.

#### Custom Nested Claims
```yaml
require:
  authority:
    app1.example.com: ["admin", "superuser"]
```

```json
{
  "iss": "auth.example.com",
  "authority": {
    "app1.example.com": ["user", "admin"],
    "app2.example.com": ["user"]
  }
}
```

### Examples

#### Interactive webserver with redirection to login and error pages
```yaml
http:
  middlewares:
    secure-web:
      plugin:
        jwt:
          issuers:
            - https://auth.example.com
          require:
            aud: test.example.com
          redirectUnauthorized: "https://example.com/login?return_to={{`{{URLQueryEscape .URL}}`}}"
          redirectForbidden: "https://example.com/unauthorized"
```

#### Configuring API and interactive endpoints together effectively
```yaml
http:
  middlewares:
    secure-api:
      plugin:
        jwt:
          &secure-api
          issuers:
            - https://auth.example.com
          require:
            aud: test.example.com

    secure-web:
      plugin:
        jwt:
          <<: *secure-api
          redirectUnauthorized: "https://example.com/login?return_to={{`{{URLQueryEscape .URL}}`}}"
          redirectForbidden: "https://example.com/unauthorized"
```

#### Specifying a fixed ECDSA public key
```yaml
http:
  middlewares:
    secure-web:
      plugin:
        jwt:
          secret: |
            -----BEGIN EC PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEE7gFCo/g2PQmC3i5kIqVgCCzr2D1
            nbCeipqfvK1rkqmKfhb7rlVehfC7ITUAy8NIvQ/AsXClvgHDv55BfOoL6w==
            -----END EC PUBLIC KEY-----
          require:
            aud: test.example.com
```

#### Specifying some known public keys upfront without prefetching them
```yaml
http:
  middlewares:
    secure-web:
      plugin:
        jwt:
          issuers:
            - https://auth.example.com
          skipPrefetch: true
          secrets:
            b5c252d9c851331f41ae99d90e0847f7da9b6568: |
              -----BEGIN EC PUBLIC KEY-----
              MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEE7gFCo/g2PQmC3i5kIqVgCCzr2D1
              nbCeipqfvK1rkqmKfhb7rlVehfC7ITUAy8NIvQ/AsXClvgHDv55BfOoL6w==
              -----END EC PUBLIC KEY-----
            b6a5717df9dc13c9b15aab32dc811fd38144d43c: |
              -----BEGIN RSA PUBLIC KEY-----
              MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzAOwEhcoj+yqyJK0Czvu
              COVoUdpaCYGeoeMB2gpclh5bHTqdfjrbko/tLpvkLKXliuWGwMMT5YC/WbhsWeAS
              ak3FMXUNGhuMoM3SebygwFNpF/kBQLayPcrlP0JtwIDEEkpWpE8b0D1GwzwbU73T
              Zedw0xrHMtH0YDbY5Q/G5/FW6wnZYOzLZdogOX0eSTlRy5T+DlYL6oDpdvqKKHGe
              gdP4r2ZVZ3CjWBcx4mERJTriGwlDkoHs/Zpvv2T+uBRSWmRnxaI62r2Nr9DJIh47
              DG7dq6bMdUOWOBRc9yBmgTF+K8/3JwDJo5JjCP9WfqAV8qtxA9g99mpbvAAqMGqa
              0QIDAQAB
              -----END RSA PUBLIC KEY-----
          require:
            aud: test.example.com
```

#### Don't verify TLS for auth.example.com
```yaml
http:
  middlewares:
    secure-web:
      plugin:
        jwt:
          issuers:
            - https://auth.example.com
          insecureSkipVerify:
            - auth.example.com
          require:
            aud: test.example.com
          redirectUnauthorized: "https://example.com/login?return_to={{`{{URLQueryEscape .URL}}`}}"
          redirectForbidden: "https://example.com/unauthorized"
```

## Forking
If you require some different behaviour, please do raise an issue or pull request in GitHub in the first instance rather than simply forking and modifying, and we'll try to accommodate it promptly (so 
as to reduce fragmentation of functionality).

## Acknowledgements

Inspired by code from https://github.com/legege/jwt-validation-middleware, https://github.com/23deg/jwt-middleware and https://github.com/team-carepay/traefik-jwt-plugin
