//! M365 Auth Command
//!
//! Initializes authentication extensions on the ExecutionContext:
//! - oauth2::reqwest::Client for HTTP requests
//! - SessionStore for managing authenticated sessions across scopes

use crate::auth::{AuthScope, SessionStore};
use oauth2::reqwest;
use panopticon_core::extend::*;
use panopticon_core::prelude::*;

// ─── CommandSchema ─────────────────────────────────────────────────────────

static M365_AUTH_SPEC: CommandSchema = LazyLock::new(|| {
    let (pending, fields) = CommandSpecBuilder::new().array_of_objects(
        "sessions",
        true,
        Some("Array of auth session configurations"),
    );

    let (fields, _) = fields.add_literal(
        "client_id",
        TypeDef::Scalar(ScalarType::String),
        true,
        Some("Azure AD App Registration Client ID (UUID)"),
    );
    let (fields, _) = fields.add_literal(
        "tenant_id",
        TypeDef::Scalar(ScalarType::String),
        true,
        Some("Azure AD Tenant ID (UUID)"),
    );
    let (fields, _) = fields.add_literal(
        "scopes",
        TypeDef::ArrayOf(Box::new(TypeDef::Scalar(ScalarType::String))),
        true,
        Some("OAuth2 scopes (e.g., https://graph.microsoft.com/.default)"),
    );

    pending
        .finalise_attribute(fields)
        .fixed_result(
            "sessions_initialized",
            TypeDef::Scalar(ScalarType::Number),
            Some("Number of sessions successfully initialized"),
            ResultKind::Meta,
        )
        .build()
});

// ─── Command Struct ────────────────────────────────────────────────────────

pub struct M365AuthCommand {
    sessions: Vec<SessionConfig>,
}

struct SessionConfig {
    client_id: String,
    tenant_id: String,
    scopes: Vec<String>,
}

// ─── Descriptor ────────────────────────────────────────────────────────────

impl Descriptor for M365AuthCommand {
    fn command_type() -> &'static str {
        "M365AuthCommand"
    }
    fn command_attributes() -> &'static [AttributeSpec<&'static str>] {
        &M365_AUTH_SPEC.0
    }
    fn command_results() -> &'static [ResultSpec<&'static str>] {
        &M365_AUTH_SPEC.1
    }
}

// ─── FromAttributes ────────────────────────────────────────────────────────

impl FromAttributes for M365AuthCommand {
    fn from_attributes(attrs: &Attributes) -> Result<Self> {
        let sessions_value = attrs
            .get("sessions")
            .ok_or_else(|| anyhow::anyhow!("Missing required attribute: sessions"))?;

        let sessions_array = sessions_value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("sessions must be an array"))?;

        let mut sessions = Vec::new();
        for item in sessions_array {
            let obj = item
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("Each session must be an object"))?;

            let client_id = obj
                .get("client_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing client_id in session"))?
                .to_string();

            let tenant_id = obj
                .get("tenant_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing tenant_id in session"))?
                .to_string();

            let scopes_value = obj
                .get("scopes")
                .ok_or_else(|| anyhow::anyhow!("Missing scopes in session"))?;

            let scopes_array = scopes_value
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("scopes must be an array"))?;

            let scopes: Vec<String> = scopes_array
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .ok_or_else(|| anyhow::anyhow!("scope must be a string"))
                })
                .collect::<Result<Vec<_>>>()?;

            sessions.push(SessionConfig {
                client_id,
                tenant_id,
                scopes,
            });
        }

        Ok(Self { sessions })
    }
}

// ─── Executable ────────────────────────────────────────────────────────────

#[async_trait]
impl Executable for M365AuthCommand {
    async fn execute(&self, context: &ExecutionContext, output_prefix: &StorePath) -> Result<()> {
        // Install reqwest::Client if not present, then clone for use
        let http: reqwest::Client = {
            let mut ext = context.extensions().write().await;
            if !ext.contains::<reqwest::Client>() {
                let client = reqwest::ClientBuilder::new()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?;
                ext.insert(client);
            }
            ext.get::<reqwest::Client>()
                .ok_or_else(|| anyhow::anyhow!("Failed to get http client"))?
                .clone() // reqwest::Client is cheap to clone (Arc internally)
        };

        // Install SessionStore if not present
        {
            let mut ext = context.extensions().write().await;
            if !ext.contains::<SessionStore>() {
                ext.insert(SessionStore::default());
            }
        }

        let services = context.services();
        let mut count = 0u64;

        // Loop through session configs and authenticate each
        for config in &self.sessions {
            // Notify user which session is being initialized
            services
                .notify(&format!(
                    "Initializing session for tenant: {}, client: {}",
                    config.tenant_id, config.client_id
                ))
                .await?;

            let scope = AuthScope {
                client_id: config.client_id.clone(),
                tenant_id: config.tenant_id.clone(),
                scopes: config.scopes.clone(),
            };

            // Get mutable access to SessionStore and trigger device code flow
            // Pass http client and services directly to avoid nested extension access
            {
                let mut ext = context.extensions().write().await;
                let store = ext
                    .get_mut::<SessionStore>()
                    .ok_or_else(|| anyhow::anyhow!("SessionStore not found"))?;

                store
                    .get_secret(&scope, &http, &services)
                    .await
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Failed to authenticate session for tenant: {}",
                            config.tenant_id
                        )
                    })?;
            }

            count += 1;
        }

        let out = InsertBatch::new(context, output_prefix);
        out.u64("sessions_initialized", count).await?;

        Ok(())
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn load_test_env() -> (String, String) {
        // Load .env file from project root
        dotenvy::dotenv().ok();

        let client_id = std::env::var("TEST_CLIENT_ID")
            .expect("TEST_CLIENT_ID env var is required for tests");
        let tenant_id = std::env::var("TEST_TENANT_ID")
            .expect("TEST_TENANT_ID env var is required for tests");

        (client_id, tenant_id)
    }

    #[tokio::test]
    #[ignore] // Requires interactive device code flow
    async fn test_m365_auth_command() -> anyhow::Result<()> {
        let (client_id, tenant_id) = load_test_env();

        let services = PipelineServices::defaults();
        let mut pipeline = Pipeline::with_services(services);

        // Build attributes with a single session config
        let attrs = ObjectBuilder::new()
            .insert(
                "sessions",
                ScalarValue::Array(vec![ObjectBuilder::new()
                    .insert("client_id", client_id.as_str())
                    .insert("tenant_id", tenant_id.as_str())
                    .insert(
                        "scopes",
                        ScalarValue::Array(vec![
                            ScalarValue::String("offline_access".to_string()),
                            ScalarValue::String(
                                "https://graph.microsoft.com/.default".to_string(),
                            ),
                        ]),
                    )
                    .build_scalar()]),
            )
            .build_hashmap();

        // Add namespace and command
        pipeline
            .add_namespace(NamespaceBuilder::new("auth"))
            .await?
            .add_command::<M365AuthCommand>("init", &attrs)
            .await?;

        // Execute the pipeline
        let completed = pipeline.compile().await?.execute().await?;
        let results = completed.results(ResultSettings::default()).await?;

        // Check results
        let source = StorePath::from_segments(["auth", "init"]);
        let cmd_results = results
            .get_by_source(&source)
            .expect("Expected auth.init results");

        let sessions_initialized = cmd_results
            .meta_get(&source.with_segment("sessions_initialized"))
            .expect("Expected sessions_initialized metadata");

        println!("Sessions initialized: {}", sessions_initialized);
        assert_eq!(sessions_initialized.to_string(), "1");

        Ok(())
    }
}
