/*
    Types:
    * SessionStore - Simple map of Sessions by a key, the key is the scope(s), client_id, and tenant_id (we'll call this an AuthScope).
    * AuthScope - Struct that defines the scope of an auth token, contains client_id, tenant_id, and scopes.
    * ConfiguredClient - The OAuth2 client type configured with the appropriate endpoints for M365 auth flows, used to acquire tokens.
    * Token - Struct that contains the actual token string, expiry time, and any other relevant metadata.
    * Session - Struct that contains the AuthScope and Token, represents an authenticated session for a given scope.

    Going to use the
*/

use oauth2::basic::BasicClient;
use oauth2::reqwest;
use oauth2::{
    AuthUrl, ClientId, DeviceAuthorizationUrl, Scope, StandardDeviceAuthorizationResponse,
    TokenResponse, TokenUrl,
};
use oauth2::{EndpointNotSet, EndpointSet};
use panopticon_core::extend::*;
use panopticon_core::prelude::PipelineServices;
use std::collections::{BTreeSet, HashMap};
use std::time::Instant;
use uuid::Uuid;

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

impl SessionStore {
    /// Get or create a session, triggering device code flow if needed.
    /// Takes http client and services directly to avoid nested extension access.
    pub async fn get_secret(
        &mut self,
        scope: &AuthScope,
        http: &reqwest::Client,
        services: &PipelineServices,
    ) -> Option<String> {
        let session = match self.sessions.get_mut(scope) {
            Some(session) => session,
            None => {
                let new_session = Session::init(scope, http, services).await.ok()?;
                self.sessions.insert(scope.clone(), new_session);
                self.sessions.get_mut(scope)?
            }
        };
        session.secret(http).await.ok()
    }
}

impl Session {
    /// Initialize a new session via device code flow.
    /// Takes http client and services directly to avoid nested extension access.
    pub async fn init(
        scope: &AuthScope,
        http: &reqwest::Client,
        services: &PipelineServices,
    ) -> Result<Self> {
        // Public client — no client secret needed for device code flow.
        let client = BasicClient::new(ClientId::new(scope.client_id.to_string()))
            .set_auth_uri(AuthUrl::new(authorization_endpoint!(scope.tenant_id))?)
            .set_token_uri(TokenUrl::new(token_endpoint!(scope.tenant_id))?)
            .set_device_authorization_url(DeviceAuthorizationUrl::new(
                device_authorization_endpoint!(scope.tenant_id),
            )?);

        // Step 1: Request a device code from the /devicecode endpoint.
        let details: StandardDeviceAuthorizationResponse = client
            .exchange_device_code()
            .add_scopes(scope.scopes.iter().map(|s| Scope::new(s.to_string())))
            .request_async(http)
            .await?;

        // Step 2: Tell the user to authenticate via their browser
        services
            .notify(&format!(
                "Open {} and enter the code: {}",
                details.verification_uri().as_str(),
                details.user_code().secret()
            ))
            .await?;

        // Step 3: Poll the token endpoint until the user completes sign-in.
        let token_result = client
            .exchange_device_access_token(&details)
            .request_async(http, tokio::time::sleep, None)
            .await?;

        Ok(Self {
            oauth: client,
            token: token_result,
            created: Instant::now(),
        })
    }

    // Refresh the token
    async fn refresh(&mut self, http: &reqwest::Client) -> Result<()> {
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

    /// Get the access token secret, refreshing if needed.
    /// Takes http client directly to avoid nested extension access.
    pub async fn secret(&mut self, http: &reqwest::Client) -> Result<String> {
        // If token is expiring in the next 5 minutes, refresh it
        let expires_in = self.token.expires_in().unwrap_or_default().as_secs();
        if expires_in < 300 || self.created.elapsed().as_secs() >= (expires_in - 300) {
            self.refresh(http).await?;
        }

        Ok(self.token.access_token().secret().to_string())
    }
}
