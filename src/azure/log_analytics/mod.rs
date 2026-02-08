pub mod query;

/// Log Analytics API base URL
pub const BASE_URL: &str = "https://api.loganalytics.azure.com";

/// API version
pub const API_VERSION: &str = "v1";

/// Target for workspace-scoped Log Analytics queries
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    workspace_id: String,
}

impl Target {
    pub fn new(workspace_id: String) -> Self {
        Self { workspace_id }
    }

    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    /// Build query URL for this workspace
    pub fn query_url(&self) -> String {
        format!(
            "{}/{}/workspaces/{}/query",
            BASE_URL, API_VERSION, self.workspace_id
        )
    }
}

impl TryFrom<&str> for Target {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(anyhow::anyhow!("Workspace ID cannot be empty"));
        }
        // Basic GUID format validation (8-4-4-4-12 with hyphens)
        if trimmed.len() != 36 || trimmed.chars().filter(|c| *c == '-').count() != 4 {
            return Err(anyhow::anyhow!(
                "Workspace ID must be a valid GUID (e.g., 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx')"
            ));
        }
        Ok(Target::new(trimmed.to_string()))
    }
}

/// Target for resource-scoped Log Analytics queries
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceTarget {
    resource_path: String,
}

impl ResourceTarget {
    pub fn new(resource_path: String) -> Self {
        Self { resource_path }
    }

    pub fn resource_path(&self) -> &str {
        &self.resource_path
    }

    /// Build query URL for this resource
    pub fn query_url(&self) -> String {
        format!(
            "{}/{}/{}/query",
            BASE_URL,
            API_VERSION,
            self.resource_path.trim_start_matches('/')
        )
    }
}

impl TryFrom<&str> for ResourceTarget {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !value.contains("/subscriptions/") {
            return Err(anyhow::anyhow!(
                "Resource path must be a valid Azure resource ID starting with /subscriptions/"
            ));
        }
        Ok(ResourceTarget::new(value.to_string()))
    }
}
