use oauth2::reqwest;

use super::LogAnalyticsWorkspace;
use crate::apis::ApiScope;
use crate::types::azure::log_analytics::MetadataResponse;

pub struct Metadata<'a> {
    pub(crate) scope: &'a LogAnalyticsWorkspace<'a>,
}

impl Metadata<'_> {
    /// GET /v1/workspaces/{workspaceId}/metadata
    ///
    /// Returns metadata about the workspace including available tables,
    /// functions, and their schemas.
    pub async fn get(&self) -> anyhow::Result<MetadataResponse> {
        let url = self.scope.url("metadata");
        let resp: MetadataResponse = self
            .scope
            .client()
            .request(self.scope.tenant_id(), reqwest::Method::GET, &url)
            .await?
            .send()
            .await?
            .json()
            .await?;
        Ok(resp)
    }
}
