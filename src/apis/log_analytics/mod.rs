pub mod metadata;
pub mod query;

use crate::apis::ApiScope;
use crate::client::Client;

pub struct LogAnalyticsWorkspace<'a> {
    pub(crate) client: &'a Client,
    pub(crate) tenant_id: &'a str,
    workspace_id: &'a str,
}

impl ApiScope for LogAnalyticsWorkspace<'_> {
    fn client(&self) -> &Client {
        self.client
    }

    fn tenant_id(&self) -> &str {
        self.tenant_id
    }

    fn url(&self, suffix: &str) -> String {
        format!(
            "https://api.loganalytics.io/v1/workspaces/{}/{}",
            self.workspace_id,
            suffix.trim_start_matches('/')
        )
    }
}

impl<'a> LogAnalyticsWorkspace<'a> {
    pub fn new(client: &'a Client, tenant_id: &'a str, workspace_id: &'a str) -> Self {
        Self {
            client,
            tenant_id,
            workspace_id,
        }
    }

    pub fn metadata(&self) -> metadata::Metadata<'_> {
        metadata::Metadata { scope: self }
    }

    pub fn query(&self) -> query::Query<'_> {
        query::Query { scope: self }
    }
}
