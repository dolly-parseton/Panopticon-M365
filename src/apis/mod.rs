pub mod log_analytics;
pub mod resource_manager;
pub mod sentinel;

use oauth2::reqwest;
use serde::de::DeserializeOwned;

use crate::client::Client;
use crate::types::azure::common::ListResponse;

// ── ApiScope ────────────────────────────────────────────────────────────────
//
// A scoped API surface that can construct authenticated requests.
//
// Each implementation encodes the base URL, path prefix, and versioning
// strategy for a particular Microsoft API surface:
//
//   - ARM / Resource Manager  → management.azure.com  + ?api-version query
//   - Sentinel (ARM sub-scope)→ same base, deep provider prefix, shared version
//   - Microsoft Graph         → graph.microsoft.com/v1.0, no query-param version
//   - Office 365 Management   → manage.office.com/api/v1.0
//
// Generic helpers (`list_resources`, `get_resource`, …) are written once
// against this trait and work across every surface.

pub trait ApiScope {
    fn client(&self) -> &Client;
    fn tenant_id(&self) -> &str;

    /// Build a full request URL from a resource-relative suffix.
    ///
    /// The suffix may contain query parameters (e.g.
    /// `"subscriptions?api-version=2022-12-01"`) or be a bare path
    /// (e.g. `"incidents"`) if the scope appends versioning itself.
    fn url(&self, suffix: &str) -> String;
}

// ── Generic helpers ─────────────────────────────────────────────────────────

/// GET a paginated list, accumulating pages via `nextLink` / `@odata.nextLink`.
/// Each raw item is converted to the domain type via `From`.
pub async fn list_resources<Raw, Domain>(
    scope: &impl ApiScope,
    suffix: &str,
) -> anyhow::Result<Vec<Domain>>
where
    Raw: DeserializeOwned,
    Domain: From<Raw>,
{
    let resp: ListResponse<Raw> = scope
        .client()
        .request(scope.tenant_id(), reqwest::Method::GET, &scope.url(suffix))
        .await?
        .send()
        .await?
        .json()
        .await?;

    let mut items: Vec<Domain> = resp.value.into_iter().map(Domain::from).collect();
    let mut next_link = resp.next_link;

    while let Some(url) = next_link {
        let page: ListResponse<Raw> = scope
            .client()
            .request(scope.tenant_id(), reqwest::Method::GET, &url)
            .await?
            .send()
            .await?
            .json()
            .await?;
        items.extend(page.value.into_iter().map(Domain::from));
        next_link = page.next_link;
    }

    Ok(items)
}

/// GET a single resource and convert `Raw → Domain`.
pub async fn get_resource<Raw, Domain>(
    scope: &impl ApiScope,
    suffix: &str,
) -> anyhow::Result<Domain>
where
    Raw: DeserializeOwned,
    Domain: From<Raw>,
{
    let resp: Raw = scope
        .client()
        .request(scope.tenant_id(), reqwest::Method::GET, &scope.url(suffix))
        .await?
        .send()
        .await?
        .json()
        .await?;
    Ok(Domain::from(resp))
}

/// PUT a resource with a JSON body, returning the converted response.
pub async fn put_resource<Body, Raw, Domain>(
    scope: &impl ApiScope,
    suffix: &str,
    body: &Body,
) -> anyhow::Result<Domain>
where
    Body: serde::Serialize,
    Raw: DeserializeOwned,
    Domain: From<Raw>,
{
    let resp: Raw = scope
        .client()
        .request(scope.tenant_id(), reqwest::Method::PUT, &scope.url(suffix))
        .await?
        .json(body)
        .send()
        .await?
        .json()
        .await?;
    Ok(Domain::from(resp))
}

/// POST a resource with a JSON body, returning the converted response.
pub async fn post_resource<Body, Raw, Domain>(
    scope: &impl ApiScope,
    suffix: &str,
    body: &Body,
) -> anyhow::Result<Domain>
where
    Body: serde::Serialize,
    Raw: DeserializeOwned,
    Domain: From<Raw>,
{
    let resp: Raw = scope
        .client()
        .request(scope.tenant_id(), reqwest::Method::POST, &scope.url(suffix))
        .await?
        .json(body)
        .send()
        .await?
        .json()
        .await?;
    Ok(Domain::from(resp))
}

/// DELETE a resource. Returns `()` on success.
pub async fn delete_resource(scope: &impl ApiScope, suffix: &str) -> anyhow::Result<()> {
    scope
        .client()
        .request(
            scope.tenant_id(),
            reqwest::Method::DELETE,
            &scope.url(suffix),
        )
        .await?
        .send()
        .await?;
    Ok(())
}

// ── api_resource! macro ─────────────────────────────────────────────────────
//
// Declares an API resource group struct with auto-generated methods.
//
// # Syntax
//
//     api_resource! {
//         <Name> on <ScopeType> {
//             list   <fn>(<params>) -> Vec<Domain> from <Raw> at "<path>";
//             get    <fn>(<params>) -> <Domain>    from <Raw> at "<path>";
//             put    <fn>(<params>) -> <Domain>    from <Raw> at "<path>" with <body>: <&BodyTy>;
//             post   <fn>(<params>) -> <Domain>    from <Raw> at "<path>" with <body>: <&BodyTy>;
//             delete <fn>(<params>) at "<path>";
//         }
//     }
//
// # Endpoint verbs
//
// | Verb     | HTTP   | Pagination | Body | Return        |
// |----------|--------|------------|------|---------------|
// | `list`   | GET    | yes        | no   | `Vec<Domain>` |
// | `get`    | GET    | no         | no   | `Domain`      |
// | `put`    | PUT    | no         | yes  | `Domain`      |
// | `post`   | POST   | no         | yes  | `Domain`      |
// | `delete` | DELETE | no         | no   | `()`          |
//
// # Path interpolation
//
// Path literals use `format!` syntax. Method parameters are captured as
// named arguments:
//
//     get get(incident_id: &str) -> Incident from raw::IncidentResponse
//         at "incidents/{incident_id}";
//
// # Scope constraint
//
// `ScopeType` must be a bare ident (not a path) with exactly one lifetime
// parameter. The macro generates `struct Name<'a> { scope: &'a Scope<'a> }`.
// Import the scope type at the call site if it lives in another module.
//
// # Escape hatch
//
// Non-standard endpoints (POST-to-list, custom response wrappers, etc.)
// are added in a separate `impl` block alongside the macro invocation:
//
//     api_resource! { Incidents on SentinelWorkspace { /* standard CRUD */ } }
//
//     impl Incidents<'_> {
//         pub async fn list_alerts(&self, id: &str) -> Result<Vec<Alert>> {
//             /* manual implementation */
//         }
//     }
//
#[macro_export]
macro_rules! api_resource {
    // ── entry point ──────────────────────────────────────────────────────
    ($Name:ident on $Scope:ident { $($body:tt)* }) => {
        pub struct $Name<'a> {
            pub(crate) scope: &'a $Scope<'a>,
        }

        impl $Name<'_> {
            api_resource!(@munch $($body)*);
        }
    };

    // ── terminal ─────────────────────────────────────────────────────────
    (@munch) => {};

    // ── list: GET with pagination ────────────────────────────────────────
    (@munch
        list $method:ident($($param:ident : $param_ty:ty),*)
        -> Vec<$($domain:ident)::+> from $($raw:ident)::+ at $path:literal;
        $($rest:tt)*
    ) => {
        pub async fn $method(
            &self, $($param : $param_ty),*
        ) -> ::anyhow::Result<Vec<$($domain)::+>> {
            $crate::apis::list_resources::<$($raw)::+, $($domain)::+>(
                self.scope, &format!($path)
            ).await
        }
        api_resource!(@munch $($rest)*);
    };

    // ── get: GET single resource ─────────────────────────────────────────
    (@munch
        get $method:ident($($param:ident : $param_ty:ty),*)
        -> $($domain:ident)::+ from $($raw:ident)::+ at $path:literal;
        $($rest:tt)*
    ) => {
        pub async fn $method(
            &self, $($param : $param_ty),*
        ) -> ::anyhow::Result<$($domain)::+> {
            $crate::apis::get_resource::<$($raw)::+, $($domain)::+>(
                self.scope, &format!($path)
            ).await
        }
        api_resource!(@munch $($rest)*);
    };

    // ── put: PUT with body ───────────────────────────────────────────────
    (@munch
        put $method:ident($($param:ident : $param_ty:ty),*)
        -> $($domain:ident)::+ from $($raw:ident)::+ at $path:literal
        with $body:ident : $body_ty:ty;
        $($rest:tt)*
    ) => {
        pub async fn $method(
            &self, $($param : $param_ty,)* $body: $body_ty
        ) -> ::anyhow::Result<$($domain)::+> {
            $crate::apis::put_resource::<_, $($raw)::+, $($domain)::+>(
                self.scope, &format!($path), $body
            ).await
        }
        api_resource!(@munch $($rest)*);
    };

    // ── post: POST with body ─────────────────────────────────────────────
    (@munch
        post $method:ident($($param:ident : $param_ty:ty),*)
        -> $($domain:ident)::+ from $($raw:ident)::+ at $path:literal
        with $body:ident : $body_ty:ty;
        $($rest:tt)*
    ) => {
        pub async fn $method(
            &self, $($param : $param_ty,)* $body: $body_ty
        ) -> ::anyhow::Result<$($domain)::+> {
            $crate::apis::post_resource::<_, $($raw)::+, $($domain)::+>(
                self.scope, &format!($path), $body
            ).await
        }
        api_resource!(@munch $($rest)*);
    };

    // ── delete: DELETE ───────────────────────────────────────────────────
    (@munch
        delete $method:ident($($param:ident : $param_ty:ty),*)
        at $path:literal;
        $($rest:tt)*
    ) => {
        pub async fn $method(
            &self, $($param : $param_ty),*
        ) -> ::anyhow::Result<()> {
            $crate::apis::delete_resource(
                self.scope, &format!($path)
            ).await
        }
        api_resource!(@munch $($rest)*);
    };
}
