mod extension;

pub use extension::{AuthEvent, M365Auth, M365_AUTH_EXT};

use oauth2::basic::BasicClient;
use oauth2::reqwest;
use oauth2::{
    AuthUrl, ClientId, DeviceAuthorizationUrl, RefreshToken, Scope,
    StandardDeviceAuthorizationResponse, TokenResponse, TokenUrl,
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

type ConfiguredClient = BasicClient<
    EndpointSet,    // HasAuthUrl
    EndpointSet,    // HasDeviceAuthUrl
    EndpointNotSet, // HasIntrospectionUrl
    EndpointNotSet, // HasRevocationUrl
    EndpointSet,    // HasTokenUrl
>;

pub type Token =
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>;

/// Identifies a client/tenant pair. Used to key the session store, since a single
/// interactive auth produces a refresh token that can silently acquire access tokens
/// for any resource scope within that tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TenantKey {
    pub client_id: String,
    pub tenant_id: String,
}

/// Parameters for the initial interactive device code flow.
/// After authentication, subsequent scopes are acquired silently via refresh token.
#[derive(Debug, Clone)]
pub struct AuthScope {
    pub client_id: String,
    pub tenant_id: String,
    /// Scopes to request during the interactive flow (should include `offline_access`).
    pub scopes: Vec<String>,
}

impl AuthScope {
    fn tenant_key(&self) -> TenantKey {
        TenantKey {
            client_id: self.client_id.clone(),
            tenant_id: self.tenant_id.clone(),
        }
    }
}

/// A cached access token for a specific scope.
struct CachedToken {
    access_token: String,
    created: Instant,
    expires_in_secs: u64,
}

impl CachedToken {
    fn is_expiring(&self) -> bool {
        self.expires_in_secs < 300 || self.created.elapsed().as_secs() >= self.expires_in_secs.saturating_sub(300)
    }
}

/// Holds the OAuth2 client and refresh token for a client/tenant pair,
/// plus a cache of per-scope access tokens.
pub(crate) struct TenantSession {
    oauth: ConfiguredClient,
    refresh_token: RefreshToken,
    /// Access tokens keyed by scope string (e.g. "https://graph.microsoft.com/ThreatHunting.Read.All").
    tokens: HashMap<String, CachedToken>,
}

impl TenantSession {
    /// Get an access token for the given scope, using the cached value if still valid
    /// or silently acquiring a new one via refresh token exchange.
    async fn get_token(
        &mut self,
        scope: &str,
        http: &reqwest::Client,
    ) -> anyhow::Result<String> {
        // Return cached token if it's not expiring.
        if let Some(cached) = self.tokens.get(scope) {
            if !cached.is_expiring() {
                return Ok(cached.access_token.clone());
            }
        }

        // Silently acquire a new access token for this scope using the refresh token.
        let token_response = self
            .oauth
            .exchange_refresh_token(&self.refresh_token)
            .add_scope(Scope::new("offline_access".to_string()))
            .add_scope(Scope::new(scope.to_string()))
            .request_async(http)
            .await?;

        // Update the refresh token if a new one was issued.
        if let Some(new_refresh) = token_response.refresh_token() {
            self.refresh_token = new_refresh.clone();
        }

        let access_token = token_response.access_token().secret().to_string();
        let expires_in_secs = token_response.expires_in().unwrap_or_default().as_secs();

        self.tokens.insert(
            scope.to_string(),
            CachedToken {
                access_token: access_token.clone(),
                created: Instant::now(),
                expires_in_secs,
            },
        );

        Ok(access_token)
    }
}

pub struct SessionStore {
    sessions: HashMap<TenantKey, TenantSession>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}

impl SessionStore {
    /// Get an access token for a specific scope within an authenticated tenant.
    /// Silently acquires new tokens via refresh token — no user interaction needed.
    pub async fn get_token(
        &mut self,
        key: &TenantKey,
        scope: &str,
        http: &reqwest::Client,
    ) -> Option<anyhow::Result<String>> {
        let session = self.sessions.get_mut(key)?;
        Some(session.get_token(scope, http).await)
    }

    pub fn has_session(&self, key: &TenantKey) -> bool {
        self.sessions.contains_key(key)
    }

    pub(crate) fn insert(&mut self, key: TenantKey, session: TenantSession) {
        self.sessions.insert(key, session);
    }
}

/// Run the interactive device code flow, returning a `TenantSession` with a
/// refresh token that can silently acquire tokens for other scopes.
pub(crate) async fn device_code_flow(
    scope: &AuthScope,
    http: &reqwest::Client,
    tx: &mpsc::Sender<AuthEvent>,
) -> anyhow::Result<(TenantKey, TenantSession)> {
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

    let refresh_token = token_result
        .refresh_token()
        .ok_or_else(|| anyhow::anyhow!("No refresh token returned — ensure offline_access scope is requested"))?
        .clone();

    // Cache the initial access token for the requested scopes.
    let access_token = token_result.access_token().secret().to_string();
    let expires_in_secs = token_result.expires_in().unwrap_or_default().as_secs();

    let mut tokens = HashMap::new();
    // Cache the token under each non-utility scope that was requested.
    for s in &scope.scopes {
        if s != "offline_access" {
            tokens.insert(
                s.clone(),
                CachedToken {
                    access_token: access_token.clone(),
                    created: Instant::now(),
                    expires_in_secs,
                },
            );
        }
    }

    let session = TenantSession {
        oauth: client,
        refresh_token,
        tokens,
    };

    Ok((scope.tenant_key(), session))
}
