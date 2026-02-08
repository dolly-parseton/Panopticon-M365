pub mod incidents;
pub mod watchlist_items;
pub mod watchlists;

use crate::apis::ApiScope;
use crate::client::Client;

const API_VERSION: &str = "2025-09-01";

pub struct SentinelWorkspace<'a> {
    pub(crate) client: &'a Client,
    pub(crate) tenant_id: &'a str,
    subscription_id: &'a str,
    resource_group: &'a str,
    workspace_name: &'a str,
}

impl ApiScope for SentinelWorkspace<'_> {
    fn client(&self) -> &Client {
        self.client
    }

    fn tenant_id(&self) -> &str {
        self.tenant_id
    }

    fn url(&self, suffix: &str) -> String {
        format!(
            "https://management.azure.com/{}/{}?api-version={}",
            self.base_path(),
            suffix.trim_start_matches('/'),
            API_VERSION
        )
    }
}

impl<'a> SentinelWorkspace<'a> {
    pub fn new(
        client: &'a Client,
        tenant_id: &'a str,
        subscription_id: &'a str,
        resource_group: &'a str,
        workspace_name: &'a str,
    ) -> Self {
        Self {
            client,
            tenant_id,
            subscription_id,
            resource_group,
            workspace_name,
        }
    }

    fn base_path(&self) -> String {
        format!(
            "subscriptions/{}/resourceGroups/{}/providers/Microsoft.OperationalInsights/workspaces/{}/providers/Microsoft.SecurityInsights",
            self.subscription_id, self.resource_group, self.workspace_name
        )
    }

    pub fn incidents(&self) -> incidents::Incidents<'_> {
        incidents::Incidents { scope: self }
    }

    pub fn watchlists(&self) -> watchlists::Watchlists<'_> {
        watchlists::Watchlists { scope: self }
    }

    pub fn watchlist_items(&self) -> watchlist_items::WatchlistItems<'_> {
        watchlist_items::WatchlistItems { scope: self }
    }
}
