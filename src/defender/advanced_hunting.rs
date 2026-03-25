use crate::endpoint::{Endpoint, HttpMethod};
use crate::resource::M365Resource;
use serde::{Deserialize, Serialize};

/// Microsoft Graph API base URL.
pub const GRAPH_BASE_URL: &str = "https://graph.microsoft.com";

/// API version.
pub const API_VERSION: &str = "v1.0";

/// OAuth2 scope for Defender XDR Advanced Hunting (delegated).
pub const THREAT_HUNTING_SCOPE: &str = "https://graph.microsoft.com/ThreatHunting.Read.All";

// ─── Resource ────────────────────────────────────────────────────────────────

/// A Defender XDR tenant that can be targeted by advanced hunting operations.
///
/// Unlike Log Analytics workspaces, Defender XDR is a tenant-level resource
/// with no subscription or resource group — it is not an ARM resource.
#[derive(Debug, Clone)]
pub struct DefenderXdr {
    /// User-defined label (e.g. "prod-soc").
    pub label: Option<String>,
    /// Client ID for authentication.
    pub client_id: String,
    /// Tenant ID for authentication.
    pub tenant_id: String,
}

impl M365Resource for DefenderXdr {
    fn id(&self) -> &str {
        // Stable synthetic ID; tenant_id is embedded so each tenant is distinct.
        // We store the formatted string lazily — but the trait returns &str,
        // so we use tenant_id directly as the primary key.
        &self.tenant_id
    }

    fn resolve_keys(&self) -> Vec<&str> {
        let mut keys = vec![self.tenant_id.as_str()];
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
        THREAT_HUNTING_SCOPE
    }
}

// ─── Request / Response Types ────────────────────────────────────────────────

/// Request body for the `runHuntingQuery` Graph API endpoint.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct HuntingRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timespan: Option<String>,
}

/// Response from the `runHuntingQuery` Graph API endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntingResponse {
    pub schema: Vec<HuntingColumn>,
    pub results: Vec<serde_json::Map<String, serde_json::Value>>,
}

/// A column descriptor in an advanced hunting response.
/// The Graph API returns these fields in lowercase (`name`, `type`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntingColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub column_type: String,
}

impl HuntingResponse {
    /// Number of result rows returned.
    pub fn row_count(&self) -> usize {
        self.results.len()
    }

    /// Find a column descriptor by name.
    pub fn column(&self, name: &str) -> Option<&HuntingColumn> {
        self.schema.iter().find(|c| c.name == name)
    }
}

// ─── Endpoints ───────────────────────────────────────────────────────────────

/// Execute a KQL query via Defender XDR Advanced Hunting (POST).
pub struct RunHuntingQueryEndpoint;

impl Endpoint for RunHuntingQueryEndpoint {
    type Resource = DefenderXdr;
    type Request = HuntingRequest;
    type Response = HuntingResponse;

    fn method() -> HttpMethod {
        HttpMethod::Post
    }

    fn url(_resource: &DefenderXdr) -> String {
        format!(
            "{}/{}/security/runHuntingQuery",
            GRAPH_BASE_URL, API_VERSION
        )
    }
}
