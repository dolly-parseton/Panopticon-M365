use crate::resource::M365Resource;
use serde::{de::DeserializeOwned, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// Defines an API endpoint on a resource type.
///
/// Each endpoint carries its request/response types, HTTP method, and builds
/// the full URL from the resource's identity. The endpoint owns URL construction
/// because the same resource can be accessed via different API families
/// (e.g. a Log Analytics workspace via the LA service API *and* the ARM management API).
///
/// # Example
/// ```ignore
/// struct QueryEndpoint;
///
/// impl Endpoint for QueryEndpoint {
///     type Resource = LogAnalyticsWorkspace;
///     type Request = QueryRequest;
///     type Response = QueryResponse;
///
///     fn method() -> HttpMethod { HttpMethod::Post }
///     fn url(ws: &LogAnalyticsWorkspace) -> String {
///         format!("https://api.loganalytics.io/v1/workspaces/{}/query", ws.workspace_id)
///     }
/// }
/// ```
pub trait Endpoint: 'static {
    /// The resource type this endpoint operates on.
    type Resource: M365Resource;

    /// The request body type (use `()` for endpoints with no body).
    type Request: Serialize;

    /// The response type to deserialize into.
    type Response: DeserializeOwned;

    /// HTTP method for this endpoint.
    fn method() -> HttpMethod;

    /// Build the full URL for this endpoint given a resource instance.
    /// The endpoint is responsible for knowing its API base, the resource
    /// identifier format it needs, and any query parameters (e.g. api-version).
    fn url(resource: &Self::Resource) -> String;

    /// Override the resource's default auth scope for this endpoint.
    /// Returns `None` to use the resource's `default_scope()`.
    fn auth_scope() -> Option<&'static str> {
        None
    }

    /// Resolve the full auth scope -- endpoint override or resource default.
    fn resolved_scope() -> &'static str
    where
        Self: Sized,
    {
        Self::auth_scope().unwrap_or(<Self as Endpoint>::Resource::default_scope())
    }

    /// HTTP method as a string (for error messages).
    fn method_str() -> &'static str
    where
        Self: Sized,
    {
        Self::method().as_str()
    }
}
