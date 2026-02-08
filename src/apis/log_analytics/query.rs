use oauth2::reqwest;

use super::LogAnalyticsWorkspace;
use crate::apis::ApiScope;
use crate::types::azure::log_analytics::{QueryBody, QueryResponse};

pub struct Query<'a> {
    pub(crate) scope: &'a LogAnalyticsWorkspace<'a>,
}

impl Query<'_> {
    /// GET /v1/workspaces/{workspaceId}/query?query={query}&timespan={timespan}
    ///
    /// Execute a KQL query against the workspace via query parameters.
    pub async fn get(
        &self,
        query: &str,
        timespan: Option<&str>,
    ) -> anyhow::Result<QueryResponse> {
        let url = self.scope.url("query");
        let mut params = vec![("query", query)];
        if let Some(ts) = timespan {
            params.push(("timespan", ts));
        }

        let resp: QueryResponse = self
            .scope
            .client()
            .request(self.scope.tenant_id(), reqwest::Method::GET, &url)
            .await?
            .query(&params)
            .send()
            .await?
            .json()
            .await?;
        Ok(resp)
    }

    /// POST /v1/workspaces/{workspaceId}/query
    ///
    /// Execute a KQL query against the workspace via request body.
    /// Supports cross-workspace queries via the `workspaces` field.
    pub async fn execute(&self, body: &QueryBody) -> anyhow::Result<QueryResponse> {
        let url = self.scope.url("query");
        let resp: QueryResponse = self
            .scope
            .client()
            .request(self.scope.tenant_id(), reqwest::Method::POST, &url)
            .await?
            .json(body)
            .send()
            .await?
            .json()
            .await?;
        Ok(resp)
    }
}
