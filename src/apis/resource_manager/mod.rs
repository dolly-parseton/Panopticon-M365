pub mod resource_groups;
pub mod subscriptions;
pub mod workspaces;

use crate::apis::ApiScope;
use crate::client::Client;

pub struct ResourceManager<'a> {
    pub(crate) client: &'a Client,
    pub(crate) tenant_id: &'a str,
}

impl ApiScope for ResourceManager<'_> {
    fn client(&self) -> &Client {
        self.client
    }

    fn tenant_id(&self) -> &str {
        self.tenant_id
    }

    fn url(&self, suffix: &str) -> String {
        format!(
            "https://management.azure.com/{}",
            suffix.trim_start_matches('/')
        )
    }
}

impl<'a> ResourceManager<'a> {
    pub fn new(client: &'a Client, tenant_id: &'a str) -> Self {
        Self { client, tenant_id }
    }

    pub fn subscriptions(&self) -> subscriptions::Subscriptions<'_> {
        subscriptions::Subscriptions { scope: self }
    }

    pub fn resource_groups(&self) -> resource_groups::ResourceGroups<'_> {
        resource_groups::ResourceGroups { scope: self }
    }

    pub fn workspaces(&self) -> workspaces::Workspaces<'_> {
        workspaces::Workspaces { scope: self }
    }
}
