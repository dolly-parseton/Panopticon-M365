use super::{device_code_flow, AuthScope, SessionStore, TenantKey};
use crate::resource::M365Resource;
use panopticon_core::extend::{Extension, OperationError};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

pub const M365_AUTH_EXT: &str = "m365_auth";

#[derive(Debug, Clone)]
pub enum AuthEvent {
    DeviceCode {
        verification_uri: String,
        user_code: String,
    },
    Polling,
    Authenticated,
    Error(String),
}

pub struct M365AuthInner {
    sessions: RwLock<SessionStore>,
    http: oauth2::reqwest::Client,
    runtime: tokio::runtime::Handle,
}

/// Newtype wrapper around `Arc<M365AuthInner>` so we can implement `Extension` (orphan rules).
#[derive(Clone)]
pub struct M365Auth(Arc<M365AuthInner>);

impl Extension for M365Auth {}

impl std::ops::Deref for M365Auth {
    type Target = M365AuthInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl M365Auth {
    pub fn new(http: oauth2::reqwest::Client, runtime: tokio::runtime::Handle) -> Self {
        Self(Arc::new(M365AuthInner {
            sessions: RwLock::new(SessionStore::default()),
            http,
            runtime,
        }))
    }

    /// Start device code authentication for a client/tenant pair.
    ///
    /// Only one interactive auth is needed per (client_id, tenant_id) pair.
    /// The resulting refresh token is used to silently acquire access tokens
    /// for any resource scope within that tenant — no additional user interaction.
    ///
    /// `scope.scopes` should include `offline_access` plus at least one resource
    /// scope for the initial token (e.g. `https://api.loganalytics.io/.default`).
    pub fn authenticate(&self, scope: AuthScope) -> mpsc::Receiver<AuthEvent> {
        let (tx, rx) = mpsc::channel(16);
        let http = self.http.clone();
        let auth = self.clone();
        let runtime = self.runtime.clone();

        runtime.spawn(async move {
            let result = device_code_flow(&scope, &http, &tx).await;

            match result {
                Ok((key, session)) => {
                    let mut sessions = auth.sessions.write().unwrap();
                    sessions.insert(key, session);
                }
                Err(e) => {
                    let _ = tx.send(AuthEvent::Error(e.to_string())).await;
                }
            }
        });

        rx
    }

    /// Get a token for a specific scope within an authenticated tenant.
    ///
    /// If the scope hasn't been used before, silently acquires a new access token
    /// via refresh token exchange — no user interaction needed.
    pub fn token(
        &self,
        client_id: &str,
        tenant_id: &str,
        scope: &str,
    ) -> Result<String, OperationError> {
        let key = TenantKey {
            client_id: client_id.to_string(),
            tenant_id: tenant_id.to_string(),
        };

        let mut sessions = self.sessions.write().map_err(|_| OperationError::Custom {
            operation: "M365Auth".into(),
            message: "Failed to acquire session lock".into(),
        })?;

        let http = &self.http;
        match self.runtime.block_on(sessions.get_token(&key, scope, http)) {
            Some(Ok(token)) => Ok(token),
            Some(Err(e)) => Err(OperationError::Custom {
                operation: "M365Auth".into(),
                message: format!("Failed to acquire token for scope '{}': {}", scope, e),
            }),
            None => Err(OperationError::Custom {
                operation: "M365Auth".into(),
                message: format!(
                    "No authenticated session for tenant (client: {}, tenant: {}). \
                     Call authenticate() first.",
                    client_id, tenant_id
                ),
            }),
        }
    }

    /// Get a token for a resource using its auth context.
    ///
    /// Resolves the scope from the endpoint override or resource default,
    /// then silently acquires the token via the tenant's refresh token.
    pub fn token_for_resource<R: M365Resource>(
        &self,
        resource: &R,
        scope_override: Option<&str>,
    ) -> Result<String, OperationError> {
        let scope = scope_override.unwrap_or(R::default_scope());
        self.token(resource.client_id(), resource.tenant_id(), scope)
    }

    pub fn http_client(&self) -> &oauth2::reqwest::Client {
        &self.http
    }

    pub fn runtime(&self) -> &tokio::runtime::Handle {
        &self.runtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AZURE_LOG_ANALYTICS_SCOPE;
    use panopticon_core::extend::*;
    use panopticon_core::prelude::*;
    use std::any::TypeId;

    struct PrintToken;

    impl Operation for PrintToken {
        fn metadata() -> OperationMetadata
        where
            Self: Sized,
        {
            OperationMetadata {
                name: "PrintToken",
                description: "Retrieves a token from M365Auth and outputs its length",
                inputs: &[
                    InputSpec {
                        name: "client_id",
                        ty: Type::Text,
                        required: true,
                        default: None,
                        description: "Azure AD client ID",
                    },
                    InputSpec {
                        name: "tenant_id",
                        ty: Type::Text,
                        required: true,
                        default: None,
                        description: "Azure AD tenant ID",
                    },
                ],
                outputs: &[OutputSpec {
                    name: NameSpec::Static("token_length"),
                    ty: Type::Integer,
                    description: "Length of the retrieved token",
                    scope: OutputScope::Global,
                }],
                requires_extensions: &[ExtensionSpec {
                    name: NameSpec::Static(M365_AUTH_EXT),
                    description: "M365 authentication extension",
                    type_id: || TypeId::of::<M365Auth>(),
                }],
            }
        }

        fn execute(context: &mut Context) -> Result<(), OperationError> {
            let auth = context.extension::<M365Auth>(M365_AUTH_EXT)?;
            let client_id = context.input("client_id")?.get_value()?.as_text()?;
            let tenant_id = context.input("tenant_id")?.get_value()?.as_text()?;

            let token = auth.token(client_id, tenant_id, AZURE_LOG_ANALYTICS_SCOPE)?;
            println!("Token retrieved, length: {}", token.len());

            context.set_static_output(
                "token_length",
                StoreEntry::Var {
                    value: Value::Integer(token.len() as i64),
                    ty: Type::Integer,
                },
            )?;
            Ok(())
        }
    }

    fn load_test_env() -> (String, String) {
        dotenvy::dotenv().ok();
        let client_id =
            std::env::var("TEST_CLIENT_ID").expect("TEST_CLIENT_ID env var is required");
        let tenant_id =
            std::env::var("TEST_TENANT_ID").expect("TEST_TENANT_ID env var is required");
        (client_id, tenant_id)
    }

    #[tokio::test]
    #[ignore] // Requires interactive device code flow
    async fn test_m365_auth_extension() -> anyhow::Result<()> {
        let (client_id, tenant_id) = load_test_env();

        // 1. Create the extension
        let http = oauth2::reqwest::Client::new();
        let runtime = tokio::runtime::Handle::current();
        let auth = M365Auth::new(http, runtime);

        // 2. Authenticate via device code (before pipeline) — one interactive auth
        let scope = AuthScope {
            client_id: client_id.clone(),
            tenant_id: tenant_id.clone(),
            scopes: vec![
                "offline_access".to_string(),
                AZURE_LOG_ANALYTICS_SCOPE.to_string(),
            ],
        };

        let mut rx = auth.authenticate(scope);
        while let Some(event) = rx.recv().await {
            match event {
                AuthEvent::DeviceCode {
                    verification_uri,
                    user_code,
                } => {
                    println!("Open {} and enter the code: {}", verification_uri, user_code);
                }
                AuthEvent::Polling => {
                    println!("Waiting for authentication...");
                }
                AuthEvent::Authenticated => {
                    println!("Authentication successful!");
                    break;
                }
                AuthEvent::Error(e) => {
                    panic!("Authentication failed: {}", e);
                }
            }
        }

        // 3. Register on pipeline during Draft phase
        let mut pipe = Pipeline::default();
        pipe.var("client_id", client_id.as_str())?;
        pipe.var("tenant_id", tenant_id.as_str())?;
        pipe.extension(M365_AUTH_EXT, auth.clone());

        // 4. Add a step that uses the token
        pipe.step::<PrintToken>(
            "print_token",
            params!(
                "client_id" => Param::reference("client_id"),
                "tenant_id" => Param::reference("tenant_id"),
            ),
        )?;

        // 5. Run the pipeline
        let complete = pipe.compile()?.run().wait()?;
        complete.debug();

        Ok(())
    }
}
