/*
    Auth notes:
    * Weighed up a few options, the best seems like using oauth2 crate and single tenant App Registrations with device code flow for user auth.
    * Multi-tenant apps would be silly, not building some SaaS shit
    * This way the app doesn't actually get assigned anything except User.Read permissions, all access is via the user's permissions (this _should_ include any Azure Lighthouse access)


    I am however having some issues:

    "invalid_request: The provided value for the input parameter 'redirect_uri' is not valid. The expected value is a URI which matches a redirect URI registered for this client application."

    I think it's just being slow to propagate the redirect URIs I set in the portal. I'll test again later.

    Fix: Issue was the account I was using, although in the tenant was technically a personal account used to create the tenant, the auth resolved to the wrong app basically.
        Ran it with a test account in that tenant and it's working fine.
*/
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

/*
    So the tests work, the content of these tests should basically be how the auth flow works.
    What I need to do now is embed it into a TokenStore type that can manage tokens per-tenant and refresh them as needed.

    The token store can block on sign-in (device code flow) if no valid token is present for a tenant.
    On access to a token it checks expiry and refreshes if needed.
*/

use oauth2::basic::BasicClient;
use oauth2::reqwest;
use oauth2::{
    AuthUrl, ClientId, DeviceAuthorizationUrl, Scope, StandardDeviceAuthorizationResponse,
    TokenResponse, TokenUrl,
};
use oauth2::{EndpointNotSet, EndpointSet};
use panopticon_core::extend::*;
use std::collections::{BTreeSet, HashMap};
use std::time::Instant;
use uuid::Uuid;

/*
    Types:
    * ConfiguredClient - oauth2 BasicClient
    * Token - holds a token and its metadata
    * TokenStore - holds tokens per-tenant/client/scopes
    * TokenKey - key to identify tokens uniquely (tenant_id, client_id, scopes)
*/

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

impl Session {
    // Goes through the device code flow to create a new session
    pub async fn from_session_key(key: &SessionKey, http: &reqwest::Client) -> Result<Self> {
        // Public client — no client secret needed for device code flow.
        let client = BasicClient::new(ClientId::new(key.client_id.to_string()))
            .set_auth_uri(AuthUrl::new(authorization_endpoint!(key.tenant_id))?)
            .set_token_uri(TokenUrl::new(token_endpoint!(key.tenant_id))?)
            .set_device_authorization_url(DeviceAuthorizationUrl::new(
                device_authorization_endpoint!(key.tenant_id),
            )?);

        // Step 1: Request a device code from the /devicecode endpoint.
        let details: StandardDeviceAuthorizationResponse = client
            .exchange_device_code()
            .add_scopes(key.scopes().map(|s| Scope::new(s.to_string())))
            .request_async(http)
            .await?;

        // Step 2: Tell the user to authenticate via their browser.
        println!(
            "Open {} and enter the code: {}",
            details.verification_uri().as_str(),
            details.user_code().secret()
        );

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

    async fn secret(&mut self, http: &reqwest::Client) -> Result<&str> {
        // If token is expiring in the next 5 minutes, refresh it TODO determine if I want this to be configurable
        let expires_in = self.token.expires_in().unwrap_or_default().as_secs();
        if expires_in < 300 || self.created.elapsed().as_secs() >= (expires_in - 300) {
            self.refresh(http).await?;
        }

        Ok(self.token.access_token().secret())
    }

    // Return a reqwest request builder with the bearer token applied
    pub async fn request(
        &mut self,
        http: &reqwest::Client,
        method: reqwest::Method,
        url: &str,
    ) -> Result<reqwest::RequestBuilder> {
        let token_secret = self.secret(http).await?.to_string();
        let builder = http.request(method, url).bearer_auth(token_secret);
        Ok(builder)
    }
}

// Key to identify tokens uniquely
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct SessionKey {
    tenant_id: Uuid,
    client_id: Uuid,
    scopes: BTreeSet<String>,
}

impl SessionKey {
    // Create a new SessionKey
    pub fn new<T: Into<String>>(
        tenant_id: Uuid,
        client_id: Uuid,
        scopes: impl IntoIterator<Item = T>,
    ) -> Self {
        let scopes_set: BTreeSet<String> = scopes.into_iter().map(|s| s.into()).collect();
        Self {
            tenant_id,
            client_id,
            scopes: scopes_set,
        }
    }
    // Accessors
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
    pub fn client_id(&self) -> Uuid {
        self.client_id
    }
    pub fn scopes(&self) -> impl Iterator<Item = &String> {
        self.scopes.iter()
    }

    // Helpers for specific token scopes:
    pub fn graph_default(tenant_id: Uuid, client_id: Uuid, refreshable: bool) -> Self {
        let mut scopes = BTreeSet::new();
        scopes.insert("https://graph.microsoft.com/.default");
        if refreshable {
            scopes.insert("offline_access");
        }
        Self::new(tenant_id, client_id, scopes)
    }
    pub fn log_analytics_default(tenant_id: Uuid, client_id: Uuid, refreshable: bool) -> Self {
        let mut scopes = BTreeSet::new();
        scopes.insert("https://api.loganalytics.io/.default");
        if refreshable {
            scopes.insert("offline_access");
        }
        Self::new(tenant_id, client_id, scopes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CLIENT_ID: &str = "ec064767-caf0-4292-88c8-44597576b102";
    const TEST_TENANT_ID: &str = "df8dec64-bc23-40f8-bb99-02c915fd2e21";

    #[tokio::test]
    async fn device_code_flow() -> anyhow::Result<()> {
        use oauth2::basic::BasicClient;
        use oauth2::reqwest;
        use oauth2::{
            AuthUrl, ClientId, DeviceAuthorizationUrl, Scope, StandardDeviceAuthorizationResponse,
            TokenResponse, TokenUrl,
        };

        // Public client — no client secret needed for device code flow.
        let client = BasicClient::new(ClientId::new(TEST_CLIENT_ID.to_string()))
            .set_auth_uri(AuthUrl::new(authorization_endpoint!(TEST_TENANT_ID))?)
            .set_token_uri(TokenUrl::new(token_endpoint!(TEST_TENANT_ID))?)
            .set_device_authorization_url(DeviceAuthorizationUrl::new(
                device_authorization_endpoint!(TEST_TENANT_ID),
            )?);

        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        // Step 1: Request a device code from the /devicecode endpoint.
        let details: StandardDeviceAuthorizationResponse = client
            .exchange_device_code()
            .add_scope(Scope::new(
                "https://graph.microsoft.com/.default".to_string(),
            ))
            .request_async(&http_client)
            .await?;

        // Step 2: Tell the user to authenticate via their browser.
        println!(
            "Open {} and enter the code: {}",
            details.verification_uri().as_str(),
            details.user_code().secret()
        );

        // Step 3: Poll the token endpoint until the user completes sign-in.
        let token_result = client
            .exchange_device_access_token(&details)
            .request_async(&http_client, tokio::time::sleep, None)
            .await?;

        println!("Access token: {}", token_result.access_token().secret());
        if let Some(refresh) = token_result.refresh_token() {
            println!("Refresh token: {}", refresh.secret());
        }

        Ok(())
    }

    #[tokio::test]
    async fn token_refresh_flow() -> anyhow::Result<()> {
        use oauth2::basic::BasicClient;
        use oauth2::reqwest;
        use oauth2::{
            AuthUrl, ClientId, DeviceAuthorizationUrl, RefreshToken, Scope,
            StandardDeviceAuthorizationResponse, TokenResponse, TokenUrl,
        };

        let client = BasicClient::new(ClientId::new(TEST_CLIENT_ID.to_string()))
            .set_auth_uri(AuthUrl::new(authorization_endpoint!(TEST_TENANT_ID))?)
            .set_token_uri(TokenUrl::new(token_endpoint!(TEST_TENANT_ID))?)
            .set_device_authorization_url(DeviceAuthorizationUrl::new(
                device_authorization_endpoint!(TEST_TENANT_ID),
            )?);

        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        // Step 1: Obtain initial tokens via device code flow.
        let details: StandardDeviceAuthorizationResponse = client
            .exchange_device_code()
            .add_scope(Scope::new("offline_access".to_string()))
            .add_scope(Scope::new(
                "https://graph.microsoft.com/.default".to_string(),
            ))
            .request_async(&http_client)
            .await?;

        println!(
            "Open {} and enter the code: {}",
            details.verification_uri().as_str(),
            details.user_code().secret()
        );

        let token_result = client
            .exchange_device_access_token(&details)
            .request_async(&http_client, tokio::time::sleep, None)
            .await?;

        let refresh_token = token_result
            .refresh_token()
            .expect("Device code flow should return a refresh token");

        println!(
            "Initial access token: {}",
            token_result.access_token().secret()
        );
        println!("Refresh token: {}", refresh_token.secret());

        // Step 2: Use the refresh token to obtain a new access token.
        let refreshed = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.secret().to_string()))
            .add_scope(Scope::new(
                "https://graph.microsoft.com/.default".to_string(),
            ))
            .request_async(&http_client)
            .await?;

        println!(
            "Refreshed access token: {}",
            refreshed.access_token().secret()
        );
        if let Some(new_refresh) = refreshed.refresh_token() {
            println!("New refresh token: {}", new_refresh.secret());
        }

        Ok(())
    }
}
