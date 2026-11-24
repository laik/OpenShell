 Problem

 The Vault credential driver currently constructs API URLs using:

 ```rust
   address.join(&format!("v1/{path}"))
 ```

 Some enterprise Vault deployments require an additional routing prefix:

 ```text
   /v1/<lob>/auth/<kubernetes-auth-mount>/login
   /v1/<lob>/<kv-mount>/data/<secret-path>
 ```

 The driver cannot currently configure this prefix. Adding it to address produces incorrect path ordering or duplicates /v1/.

 This limitation was verified in v0.1.7–v0.1.9, v0.1.10-pre.3, and the inspected main revision.

 Proposed configuration

 Add an optional lob field under the Vault credential driver configuration:

 ```toml
   [openshell.credential_drivers.vault]
   address = "https://vault.example.com:8200"
   lob = "business-unit"
   auth_method = "kubernetes"
   kubernetes_auth_mount = "kubernetes"
   role = "openshell-gateway"
   service_account_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
   mount = "secret"
   kv_version = "2"
 ```

 Expected behavior

 ┌───────────────────────┬──────────────────────────┐
 │ Configuration         │ Generated API path       │
 ├───────────────────────┼──────────────────────────┤
 │ lob omitted           │ /v1/{path}               │
 ├───────────────────────┼──────────────────────────┤
 │ lob = "business-unit" │ /v1/business-unit/{path} │
 └───────────────────────┴──────────────────────────┘

 Apply this prefix consistently through the shared URL-building function to:

 - Kubernetes authentication;
 - KV reads and writes;
 - KV metadata deletion;
 - Any future token renewal or revocation requests.

 For token_file authentication, KV operations should also use the prefix.

 The prefix should not be added to logical secret paths or persisted credential handles.

 Validation and compatibility

 - Preserve existing behavior when lob is omitted.
 - Reject empty values and unsafe path segments.
 - Preserve existing HTTPS, certificate verification, no-proxy, and no-redirect protections.
 - Allow configuration through the supported Helm gateway configuration interface.

 Acceptance criteria

 1. Existing URLs remain unchanged without lob.
 2. Configuring lob inserts it immediately after /v1/.
 3. Tests cover Kubernetes and token_file authentication, plus KV v1 and v2.
 4. Invalid prefix values fail configuration validation.
 5. Stored credential handles remain resolvable after restarting with the same configuration.

 Naming consideration

 If lob is too enterprise-specific, api_path_prefix could be used instead. This request concerns URL path-prefix routing, not implicit support for the X-Vault-Namespace header.