/*
    Common and top level types for Azure. This is where the main entry point for Azure related logic should be, and where the main types that are used across the module should be defined.
*/

use crate::auth::{AuthScope, SessionStore};
use anyhow::Result;
use oauth2::reqwest;
use panopticon_core::extend::*;
use panopticon_core::prelude::*;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Azure Management API scope for ARM operations
pub const AZURE_MANAGEMENT_SCOPE: &str = "https://management.azure.com/.default";

/// Azure Log Analytics API scope
pub const AZURE_LOG_ANALYTICS_SCOPE: &str = "https://api.loganalytics.azure.com/.default";

// ─── Attribute Builders ─────────────────────────────────────────────────────

/// Standard Azure AD client_id attribute
pub fn client_id_attribute() -> AttributeSpec<&'static str> {
    AttributeSpecBuilder::new("client_id", TypeDef::Scalar(ScalarType::String))
        .required()
        .hint("Azure AD App Registration Client ID")
        .build()
}

/// Standard Azure AD tenant_id attribute
pub fn tenant_id_attribute() -> AttributeSpec<&'static str> {
    AttributeSpecBuilder::new("tenant_id", TypeDef::Scalar(ScalarType::String))
        .required()
        .hint("Azure AD Tenant ID")
        .build()
}

/// Sentinel workspace target attribute
pub fn sentinel_target_attribute() -> AttributeSpec<&'static str> {
    AttributeSpecBuilder::new("target", TypeDef::Scalar(ScalarType::String))
        .required()
        .hint("Resource path: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/")
        .build()
}

/// Incident ID attribute (reusable for incident sub-resources)
pub fn incident_id_attribute() -> AttributeSpec<&'static str> {
    AttributeSpecBuilder::new("incident_id", TypeDef::Scalar(ScalarType::String))
        .required()
        .hint("Incident ID (GUID format)")
        .build()
}

/// Log Analytics workspace ID attribute
pub fn workspace_id_attribute() -> AttributeSpec<&'static str> {
    AttributeSpecBuilder::new("workspace_id", TypeDef::Scalar(ScalarType::String))
        .required()
        .hint("Log Analytics Workspace ID (GUID)")
        .build()
}

/// KQL query attribute
pub fn query_attribute() -> AttributeSpec<&'static str> {
    AttributeSpecBuilder::new("query", TypeDef::Scalar(ScalarType::String))
        .required()
        .hint("Kusto Query Language (KQL) query")
        .build()
}

/// Timespan attribute for Log Analytics queries
pub fn timespan_attribute() -> AttributeSpec<&'static str> {
    AttributeSpecBuilder::new("timespan", TypeDef::Scalar(ScalarType::String))
        .hint("ISO 8601 duration (e.g., 'PT1H' for 1 hour, 'P1D' for 1 day)")
        .build()
}

/// Resource path attribute for resource-scoped Log Analytics queries
pub fn resource_path_attribute() -> AttributeSpec<&'static str> {
    AttributeSpecBuilder::new("resource_path", TypeDef::Scalar(ScalarType::String))
        .required()
        .hint("Azure resource path (e.g., /subscriptions/{sub}/resourceGroups/{rg}/providers/...)")
        .build()
}

// ─── Runtime Helpers ────────────────────────────────────────────────────────

/// Extract HTTP client and acquire Azure Management API token.
/// Returns (http_client, bearer_token).
pub async fn get_azure_management_token(
    context: &ExecutionContext,
    client_id: &str,
    tenant_id: &str,
) -> Result<(reqwest::Client, String)> {
    let http: reqwest::Client = {
        let ext = context.extensions().read().await;
        ext.get::<reqwest::Client>()
            .ok_or_else(|| anyhow::anyhow!("HTTP client not found. Run M365AuthCommand first."))?
            .clone()
    };

    let scope = AuthScope {
        client_id: client_id.to_string(),
        tenant_id: tenant_id.to_string(),
        scopes: vec![AZURE_MANAGEMENT_SCOPE.to_string()],
    };

    let services = context.services();
    let token = {
        let mut ext = context.extensions().write().await;
        let store = ext
            .get_mut::<SessionStore>()
            .ok_or_else(|| anyhow::anyhow!("SessionStore not found. Run M365AuthCommand first."))?;
        store
            .get_secret(&scope, &http, &services)
            .await
            .ok_or_else(|| anyhow::anyhow!("Failed to get auth token for Azure Management API"))?
    };

    Ok((http, token))
}

/// Extract HTTP client and acquire Azure Log Analytics API token.
pub async fn get_log_analytics_token(
    context: &ExecutionContext,
    client_id: &str,
    tenant_id: &str,
) -> Result<(reqwest::Client, String)> {
    let http: reqwest::Client = {
        let ext = context.extensions().read().await;
        ext.get::<reqwest::Client>()
            .ok_or_else(|| anyhow::anyhow!("HTTP client not found. Run M365AuthCommand first."))?
            .clone()
    };

    let scope = AuthScope {
        client_id: client_id.to_string(),
        tenant_id: tenant_id.to_string(),
        scopes: vec![AZURE_LOG_ANALYTICS_SCOPE.to_string()],
    };

    let services = context.services();
    let token = {
        let mut ext = context.extensions().write().await;
        let store = ext
            .get_mut::<SessionStore>()
            .ok_or_else(|| anyhow::anyhow!("SessionStore not found. Run M365AuthCommand first."))?;
        store
            .get_secret(&scope, &http, &services)
            .await
            .ok_or_else(|| anyhow::anyhow!("Failed to get auth token for Log Analytics API"))?
    };

    Ok((http, token))
}

/// Check HTTP response status and return standardized error.
/// Consumes the response on error to read the body.
pub async fn check_response_success(
    response: reqwest::Response,
    operation: &str,
) -> Result<reqwest::Response> {
    if response.status().is_success() {
        Ok(response)
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(anyhow::anyhow!(
            "Failed to {}: {} - {}",
            operation,
            status,
            body
        ))
    }
}

// ─── Descriptor Macro ───────────────────────────────────────────────────────

/// Generates the boilerplate Descriptor trait implementation.
///
/// # Example
/// ```ignore
/// impl_descriptor!(GetIncidentCommand, "GetIncidentCommand", GET_INCIDENT_SPEC);
/// ```
#[macro_export]
macro_rules! impl_descriptor {
    ($command:ty, $type_str:literal, $spec:ident) => {
        impl Descriptor for $command {
            fn command_type() -> &'static str {
                $type_str
            }
            fn command_attributes() -> &'static [AttributeSpec<&'static str>] {
                &$spec.0
            }
            fn command_results() -> &'static [ResultSpec<&'static str>] {
                &$spec.1
            }
        }
    };
}
