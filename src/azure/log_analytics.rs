use crate::endpoint::{Endpoint, HttpMethod};
use crate::resource::{AzureResource, M365Resource};
use serde::{Deserialize, Serialize};

/// Log Analytics API base URL.
pub const BASE_URL: &str = "https://api.loganalytics.io";

/// API version.
pub const API_VERSION: &str = "v1";

/// Default OAuth2 scope for the Log Analytics API.
pub const LOG_ANALYTICS_SCOPE: &str = "https://api.loganalytics.io/.default";

/// Azure Management scope (used for resource-scoped queries).
pub const MANAGEMENT_SCOPE: &str = "https://management.azure.com/.default";

// ─── Resource ────────────────────────────────────────────────────────────────

/// A Log Analytics workspace that can be targeted by query operations.
#[derive(Debug, Clone)]
pub struct LogAnalyticsWorkspace {
    /// User-defined label (e.g. "prod-soc").
    pub label: Option<String>,
    /// Workspace GUID -- used by the Log Analytics API.
    pub workspace_id: String,
    /// Full ARM resource path.
    pub arm_path: String,
    /// Subscription ID extracted from the ARM path.
    pub subscription_id: String,
    /// Resource group extracted from the ARM path.
    pub resource_group: String,
    /// Client ID for authentication.
    pub client_id: String,
    /// Tenant ID for authentication.
    pub tenant_id: String,
}

impl M365Resource for LogAnalyticsWorkspace {
    fn id(&self) -> &str {
        &self.arm_path
    }

    fn resolve_keys(&self) -> Vec<&str> {
        let mut keys = vec![self.arm_path.as_str(), self.workspace_id.as_str()];
        if let Some(label) = &self.label {
            keys.push(label.as_str());
        }
        keys
    }

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    fn default_scope() -> &'static str {
        LOG_ANALYTICS_SCOPE
    }
}

impl AzureResource for LogAnalyticsWorkspace {
    fn subscription_id(&self) -> &str {
        &self.subscription_id
    }

    fn resource_group(&self) -> &str {
        &self.resource_group
    }
}

// ─── Request / Response Types ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct QueryRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timespan: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    pub tables: Vec<QueryTable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTable {
    pub name: String,
    pub columns: Vec<QueryColumn>,
    pub rows: Vec<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub column_type: String,
}

impl QueryResponse {
    pub fn primary_table(&self) -> Option<&QueryTable> {
        self.tables
            .iter()
            .find(|t| t.name == "PrimaryResult")
            .or_else(|| self.tables.first())
    }
}

impl QueryTable {
    pub fn column_index(&self, name: &str) -> Option<usize> {
        self.columns.iter().position(|c| c.name == name)
    }
}

// ─── Endpoints ───────────────────────────────────────────────────────────────

/// Execute a KQL query against a Log Analytics workspace via the LA service API (POST).
pub struct QueryEndpoint;

impl Endpoint for QueryEndpoint {
    type Resource = LogAnalyticsWorkspace;
    type Request = QueryRequest;
    type Response = QueryResponse;

    fn method() -> HttpMethod {
        HttpMethod::Post
    }

    fn url(ws: &LogAnalyticsWorkspace) -> String {
        format!(
            "{}/{}/workspaces/{}/query",
            BASE_URL, API_VERSION, ws.workspace_id
        )
    }
}

/// Execute a KQL query via the Azure Management API (resource-scoped, POST).
/// Uses the ARM path and management scope instead of the Log Analytics service API.
pub struct ResourceQueryEndpoint;

impl Endpoint for ResourceQueryEndpoint {
    type Resource = LogAnalyticsWorkspace;
    type Request = QueryRequest;
    type Response = QueryResponse;

    fn method() -> HttpMethod {
        HttpMethod::Post
    }

    fn url(ws: &LogAnalyticsWorkspace) -> String {
        format!(
            "https://management.azure.com{}/query?api-version=2025-02-01",
            ws.arm_path
        )
    }

    fn auth_scope() -> Option<&'static str> {
        Some(MANAGEMENT_SCOPE)
    }
}
