/*
    To make all the requests simple I should make a unified HTTP client that handles all the auth token refreshing and stuff.
    I should define a few things
    * Client (struct) - holds the HTTP client, auth tokens, config, etc.
        * If we allow multi-tenant clients it'll need some kind of per-tenant token storage and interface for adding new tenants, therefore it'll also need a tenant type and I'll want to find some APIs for identifying tenants.

    * ClientConfig (struct) - holds config data for the client (consumed on Client creation, might need a builder?)
    * ??? - Some kind of interface for response handling.

    Some open questions:
    * Should a single client be able to make requests to multiple tenants? Don't see why not if auth tokens are stored per-tenant and the requests specify tenant (given the application for this I think that's fair).
    * Should the client be generic over the HTTP client implementation? Would let crate users pick their own HTTP client, would be fun to implement something like that.

    Seems like the client is a big bit of work but the more I do here the easier it'll be to add new API support and then build commands on top of that.

    ...

    Blindspots:
    * Who owns the client?
        There's no support that would enable a client to be shared across multiple commands at the moment. So each would own their own client.
        Problematic for token management and efficiency but not the end of the world.
        It doesn't feel right but a LazyLock client might work?

        This might be a blocker, if it is this client will need to be generic and added to the core library not here. ExecutionContext is an obvious place to put it.
*/
pub mod auth;

use panopticon_core::extend::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use oauth2::reqwest;

use crate::apis::log_analytics::LogAnalyticsWorkspace;
use crate::apis::resource_manager::ResourceManager;
use crate::apis::sentinel::SentinelWorkspace;

pub struct Client {
    http: reqwest::Client,
    sessions: RwLock<HashMap<auth::SessionKey, Arc<Mutex<auth::Session>>>>,
}

impl Client {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            sessions: RwLock::new(HashMap::new()),
        }
    }

    pub async fn authenticate(
        &self,
        tenant_id: &str,
        client_id: &str,
        scopes: &[&str],
    ) -> Result<()> {
        let key = auth::SessionKey::new(
            Uuid::parse_str(tenant_id)?,
            Uuid::parse_str(client_id)?,
            scopes.iter().map(|s| s.to_string()),
        );

        let mut sessions = self.sessions.write().await;
        if !sessions.contains_key(&key) {
            let session = auth::Session::from_session_key(&key, &self.http).await?;
            sessions.insert(key, Arc::new(Mutex::new(session)));
        }

        Ok(())
    }

    fn find_session(
        sessions: &HashMap<auth::SessionKey, Arc<Mutex<auth::Session>>>,
        tenant_id: &str,
    ) -> Result<Arc<Mutex<auth::Session>>> {
        let tenant_uuid = Uuid::parse_str(tenant_id)?;
        sessions
            .iter()
            .find(|(k, _)| k.tenant_id() == tenant_uuid)
            .map(|(_, v)| Arc::clone(v))
            .ok_or_else(|| anyhow::anyhow!("No session found for tenant {}", tenant_id))
    }

    pub async fn request(
        &self,
        tenant_id: &str,
        method: reqwest::Method,
        url: &str,
    ) -> Result<reqwest::RequestBuilder> {
        let session_arc = {
            let sessions = self.sessions.read().await;
            Self::find_session(&sessions, tenant_id)?
        };
        let mut session = session_arc.lock().await;
        session.request(&self.http, method, url).await
    }

    pub fn resource_manager<'a>(&'a self, tenant_id: &'a str) -> ResourceManager<'a> {
        ResourceManager::new(self, tenant_id)
    }

    pub fn sentinel<'a>(
        &'a self,
        tenant_id: &'a str,
        subscription_id: &'a str,
        resource_group: &'a str,
        workspace_name: &'a str,
    ) -> SentinelWorkspace<'a> {
        SentinelWorkspace::new(self, tenant_id, subscription_id, resource_group, workspace_name)
    }

    pub fn log_analytics<'a>(
        &'a self,
        tenant_id: &'a str,
        workspace_id: &'a str,
    ) -> LogAnalyticsWorkspace<'a> {
        LogAnalyticsWorkspace::new(self, tenant_id, workspace_id)
    }
}
