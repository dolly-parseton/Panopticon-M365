use crate::auth::M365Auth;
use crate::endpoint::{Endpoint, HttpMethod};
use panopticon_core::extend::OperationError;

/// Execute an HTTP request against an M365 endpoint.
///
/// Generic over any `Endpoint` type -- handles token acquisition, URL construction,
/// HTTP dispatch, status checking, and response deserialization. Operations call this
/// from within `execute()` after extracting their values from Context.
///
/// Safe to call from sync Operation::execute because pipeline runs on an OS thread,
/// not a tokio worker thread.
pub fn execute_endpoint<E: Endpoint>(
    auth: &M365Auth,
    resource: &E::Resource,
    request: &E::Request,
    operation_name: &'static str,
) -> Result<E::Response, OperationError> {
    let token = auth.token_for_resource(resource, E::auth_scope())?;
    let url = E::url(resource);
    let client = auth.http_client();
    let runtime = auth.runtime();

    let mut builder = match E::method() {
        HttpMethod::Get => client.get(&url),
        HttpMethod::Post => client.post(&url),
        HttpMethod::Put => client.put(&url),
        HttpMethod::Patch => client.patch(&url),
        HttpMethod::Delete => client.delete(&url),
    };

    builder = builder
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json");

    // Attach body for methods that carry one.
    match E::method() {
        HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch => {
            builder = builder.json(request);
        }
        _ => {}
    }

    let response = runtime
        .block_on(async { builder.send().await })
        .map_err(|e| OperationError::Custom {
            operation: operation_name.into(),
            message: format!("HTTP request failed: {}", e),
        })?;

    let status = response.status();
    if !status.is_success() {
        let body = runtime
            .block_on(async { response.text().await })
            .unwrap_or_default();
        let truncated = if body.len() > 500 { &body[..500] } else { &body };
        return Err(OperationError::Custom {
            operation: operation_name.into(),
            message: format!(
                "HTTP {} from {} {}: {}",
                status.as_u16(),
                E::method_str(),
                url,
                truncated
            ),
        });
    }

    runtime
        .block_on(async { response.json::<E::Response>().await })
        .map_err(|e| OperationError::Custom {
            operation: operation_name.into(),
            message: format!("Failed to deserialize response: {}", e),
        })
}
