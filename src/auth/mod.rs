mod extension;

pub use extension::{AuthEvent, M365Auth, M365_AUTH_EXT};

use oauth2::basic::BasicClient;
use oauth2::reqwest;
use oauth2::{
    AuthUrl, ClientId, DeviceAuthorizationUrl, Scope, StandardDeviceAuthorizationResponse,
    TokenResponse, TokenUrl,
};
use oauth2::{EndpointNotSet, EndpointSet};
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::mpsc;

pub const AZURE_MANAGEMENT_SCOPE: &str = "https://management.azure.com/.default";
pub const AZURE_LOG_ANALYTICS_SCOPE: &str = "https://api.loganalytics.io/.default";

macro_rules! token_endpoint {
    ($tenant_id:expr) => {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            $tenant_id
        )
    };
}
macro_rules! authorization_endpoint {
    ($tenant_id:expr) => {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
            $tenant_id
        )
    };
}
macro_rules! device_authorization_endpoint {
    ($tenant_id:expr) => {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/devicecode",
            $tenant_id
        )
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthScope {
    pub client_id: String,
    pub tenant_id: String,
    pub scopes: Vec<String>,
}

type ConfiguredClient = BasicClient<
    EndpointSet,    // HasAuthUrl
    EndpointSet,    // HasDeviceAuthUrl
    EndpointNotSet, // HasIntrospectionUrl
    EndpointNotSet, // HasRevocationUrl
    EndpointSet,    // HasTokenUrl
>;

pub type Token =
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>;

pub struct Session {
    oauth: ConfiguredClient,
    token: Token,
    created: Instant,
}

pub struct SessionStore {
    sessions: HashMap<AuthScope, Session>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}

impl SessionStore {
    /// Authenticate a scope via device code flow, sending events through the channel.
    pub async fn authenticate(
        &mut self,
        scope: &AuthScope,
        http: &reqwest::Client,
        tx: &mpsc::Sender<AuthEvent>,
    ) -> anyhow::Result<()> {
        let session = Session::init(scope, http, tx).await?;
        self.sessions.insert(scope.clone(), session);
        Ok(())
    }

    /// Get the access token for a scope, refreshing if needed.
    /// Returns None if no session exists for the scope.
    pub async fn get_token(
        &mut self,
        scope: &AuthScope,
        http: &reqwest::Client,
    ) -> Option<String> {
        let session = self.sessions.get_mut(scope)?;
        session.secret(http).await.ok()
    }

    pub fn has_session(&self, scope: &AuthScope) -> bool {
        self.sessions.contains_key(scope)
    }

    pub(crate) fn insert(&mut self, scope: AuthScope, session: Session) {
        self.sessions.insert(scope, session);
    }
}

impl Session {
    /// Initialize a new session via device code flow.
    /// Sends AuthEvents through the channel for consumer UI updates.
    pub(crate) async fn init(
        scope: &AuthScope,
        http: &reqwest::Client,
        tx: &mpsc::Sender<AuthEvent>,
    ) -> anyhow::Result<Self> {
        let client = BasicClient::new(ClientId::new(scope.client_id.to_string()))
            .set_auth_uri(AuthUrl::new(authorization_endpoint!(scope.tenant_id))?)
            .set_token_uri(TokenUrl::new(token_endpoint!(scope.tenant_id))?)
            .set_device_authorization_url(DeviceAuthorizationUrl::new(
                device_authorization_endpoint!(scope.tenant_id),
            )?);

        // Step 1: Request a device code
        let details: StandardDeviceAuthorizationResponse = client
            .exchange_device_code()
            .add_scopes(scope.scopes.iter().map(|s| Scope::new(s.to_string())))
            .request_async(http)
            .await?;

        // Step 2: Notify consumer with device code info
        let _ = tx
            .send(AuthEvent::DeviceCode {
                verification_uri: details.verification_uri().as_str().to_string(),
                user_code: details.user_code().secret().to_string(),
            })
            .await;

        // Step 3: Poll for token completion
        let _ = tx.send(AuthEvent::Polling).await;
        let token_result = client
            .exchange_device_access_token(&details)
            .request_async(http, tokio::time::sleep, None)
            .await?;

        let _ = tx.send(AuthEvent::Authenticated).await;

        Ok(Self {
            oauth: client,
            token: token_result,
            created: Instant::now(),
        })
    }

    async fn refresh(&mut self, http: &reqwest::Client) -> anyhow::Result<()> {
        let refresh_token = self
            .token
            .refresh_token()
            .ok_or_else(|| anyhow::anyhow!("No refresh token available"))?;
        let new_token = self
            .oauth
            .exchange_refresh_token(refresh_token)
            .request_async(http)
            .await?;
        self.token = new_token;
        self.created = Instant::now();
        Ok(())
    }

    /// Get the access token secret, refreshing if expiring within 5 minutes.
    async fn secret(&mut self, http: &reqwest::Client) -> anyhow::Result<String> {
        let expires_in = self.token.expires_in().unwrap_or_default().as_secs();
        if expires_in < 300 || self.created.elapsed().as_secs() >= (expires_in - 300) {
            self.refresh(http).await?;
        }
        Ok(self.token.access_token().secret().to_string())
    }
}
