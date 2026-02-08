use super::types::*;
use crate::auth::{AuthScope, SessionStore};
use crate::azure::sentinel::Target;
use oauth2::reqwest;
use panopticon_core::extend::*;
use panopticon_core::prelude::*;

// ─── Step 1: Define the CommandSchema ───────────────────────────────────────

static GET_INCIDENT_SPEC: CommandSchema = LazyLock::new(|| {
    CommandSpecBuilder::new()
        // Auth attributes (must match a session initialized by M365AuthCommand)
        .attribute(
            AttributeSpecBuilder::new("client_id", TypeDef::Scalar(ScalarType::String))
                .required()
                .hint("Azure AD App Registration Client ID (must match M365AuthCommand session)")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("tenant_id", TypeDef::Scalar(ScalarType::String))
                .required()
                .hint("Azure AD Tenant ID (must match M365AuthCommand session)")
                .build(),
        )
        // Required attributes
        .attribute(
            AttributeSpecBuilder::new("target", TypeDef::Scalar(ScalarType::String))
                .required()
                .hint("Resource ID path: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("incident_id", TypeDef::Scalar(ScalarType::String))
                .required()
                .hint("Incident ID (GUID format)")
                .build(),
        )
        // Results - Core identifiers
        .fixed_result(
            "id",
            TypeDef::Scalar(ScalarType::String),
            Some("Full ARM resource ID of the incident"),
            ResultKind::Data,
        )
        .fixed_result(
            "name",
            TypeDef::Scalar(ScalarType::String),
            Some("The incident ID (GUID)"),
            ResultKind::Data,
        )
        .fixed_result(
            "etag",
            TypeDef::Scalar(ScalarType::String),
            Some("ETag for optimistic concurrency"),
            ResultKind::Data,
        )
        // Results - Required properties
        .fixed_result(
            "title",
            TypeDef::Scalar(ScalarType::String),
            Some("The title of the incident"),
            ResultKind::Data,
        )
        .fixed_result(
            "severity",
            TypeDef::Scalar(ScalarType::String),
            Some("Incident severity: High, Medium, Low, or Informational"),
            ResultKind::Data,
        )
        .fixed_result(
            "status",
            TypeDef::Scalar(ScalarType::String),
            Some("Incident status: New, Active, or Closed"),
            ResultKind::Data,
        )
        // Results - Read-only properties
        .fixed_result(
            "incident_number",
            TypeDef::Scalar(ScalarType::Number),
            Some("The sequential incident number"),
            ResultKind::Data,
        )
        .fixed_result(
            "incident_url",
            TypeDef::Scalar(ScalarType::String),
            Some("Deep-link URL to the incident in Azure portal"),
            ResultKind::Data,
        )
        .fixed_result(
            "created_time_utc",
            TypeDef::Scalar(ScalarType::String),
            Some("The time the incident was created (ISO 8601)"),
            ResultKind::Data,
        )
        .fixed_result(
            "last_modified_time_utc",
            TypeDef::Scalar(ScalarType::String),
            Some("The time the incident was last updated (ISO 8601)"),
            ResultKind::Data,
        )
        // Results - Optional properties
        .fixed_result(
            "description",
            TypeDef::Scalar(ScalarType::String),
            Some("The description of the incident"),
            ResultKind::Data,
        )
        .fixed_result(
            "first_activity_time_utc",
            TypeDef::Scalar(ScalarType::String),
            Some("The time of the first activity in the incident (ISO 8601)"),
            ResultKind::Data,
        )
        .fixed_result(
            "last_activity_time_utc",
            TypeDef::Scalar(ScalarType::String),
            Some("The time of the last activity in the incident (ISO 8601)"),
            ResultKind::Data,
        )
        .fixed_result(
            "classification",
            TypeDef::Scalar(ScalarType::String),
            Some("Classification: Undetermined, TruePositive, BenignPositive, or FalsePositive"),
            ResultKind::Data,
        )
        .fixed_result(
            "classification_comment",
            TypeDef::Scalar(ScalarType::String),
            Some("Describes the reason the incident was closed"),
            ResultKind::Data,
        )
        .fixed_result(
            "classification_reason",
            TypeDef::Scalar(ScalarType::String),
            Some("Classification reason: SuspiciousActivity, SuspiciousButExpected, IncorrectAlertLogic, or InaccurateData"),
            ResultKind::Data,
        )
        // Results - Owner information
        .fixed_result(
            "owner_object_id",
            TypeDef::Scalar(ScalarType::String),
            Some("Azure AD object ID of the incident owner"),
            ResultKind::Data,
        )
        .fixed_result(
            "owner_email",
            TypeDef::Scalar(ScalarType::String),
            Some("Email of the incident owner"),
            ResultKind::Data,
        )
        .fixed_result(
            "owner_assigned_to",
            TypeDef::Scalar(ScalarType::String),
            Some("Display name of the incident owner"),
            ResultKind::Data,
        )
        .fixed_result(
            "owner_user_principal_name",
            TypeDef::Scalar(ScalarType::String),
            Some("User principal name of the incident owner"),
            ResultKind::Data,
        )
        // Results - Additional data
        .fixed_result(
            "alerts_count",
            TypeDef::Scalar(ScalarType::Number),
            Some("Number of alerts in the incident"),
            ResultKind::Data,
        )
        .fixed_result(
            "bookmarks_count",
            TypeDef::Scalar(ScalarType::Number),
            Some("Number of bookmarks in the incident"),
            ResultKind::Data,
        )
        .fixed_result(
            "comments_count",
            TypeDef::Scalar(ScalarType::Number),
            Some("Number of comments on the incident"),
            ResultKind::Data,
        )
        .fixed_result(
            "provider_name",
            TypeDef::Scalar(ScalarType::String),
            Some("The name of the source provider that generated the incident"),
            ResultKind::Data,
        )
        .fixed_result(
            "provider_incident_id",
            TypeDef::Scalar(ScalarType::String),
            Some("The incident ID assigned by the provider"),
            ResultKind::Data,
        )
        .build()
});

// ─── Step 2: Define the command struct ──────────────────────────────────────

pub struct GetIncidentCommand {
    // Auth
    pub client_id: String,
    pub tenant_id: String,
    // Target
    pub target: Target,
    pub incident_id: String,
}

// ─── Step 3: Implement Descriptor ───────────────────────────────────────────

impl Descriptor for GetIncidentCommand {
    fn command_type() -> &'static str {
        "GetIncidentCommand"
    }
    fn command_attributes() -> &'static [AttributeSpec<&'static str>] {
        &GET_INCIDENT_SPEC.0
    }
    fn command_results() -> &'static [ResultSpec<&'static str>] {
        &GET_INCIDENT_SPEC.1
    }
}

// ─── Step 4: Implement FromAttributes ───────────────────────────────────────

impl FromAttributes for GetIncidentCommand {
    fn from_attributes(attrs: &Attributes) -> Result<Self> {
        let client_id = attrs.get_required_string("client_id")?;
        let tenant_id = attrs.get_required_string("tenant_id")?;

        let target_str = attrs.get_required_string("target")?;
        let target = Target::try_from(target_str.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid target: {}", e))?;

        let incident_id = attrs.get_required_string("incident_id")?;

        Ok(GetIncidentCommand {
            client_id,
            tenant_id,
            target,
            incident_id,
        })
    }
}

// ─── Step 5: Implement Executable ───────────────────────────────────────────

#[async_trait]
impl Executable for GetIncidentCommand {
    async fn execute(&self, context: &ExecutionContext, output_prefix: &StorePath) -> Result<()> {
        // Get HTTP client from context extensions
        let http: reqwest::Client = {
            let ext = context.extensions().read().await;
            ext.get::<reqwest::Client>()
                .ok_or_else(|| anyhow::anyhow!("HTTP client not found. Run M365AuthCommand first."))?
                .clone()
        };

        // Build auth scope for Azure Management API
        let scope = AuthScope {
            client_id: self.client_id.clone(),
            tenant_id: self.tenant_id.clone(),
            scopes: vec!["https://management.azure.com/.default".to_string()],
        };

        // Get token from SessionStore
        let services = context.services();
        let token = {
            let mut ext = context.extensions().write().await;
            let store = ext
                .get_mut::<SessionStore>()
                .ok_or_else(|| anyhow::anyhow!("SessionStore not found. Run M365AuthCommand first."))?;
            store
                .get_secret(&scope, &http, &services)
                .await
                .ok_or_else(|| anyhow::anyhow!("Failed to get auth token for Azure Management API"))?
        };

        // Build the API URL
        let url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.OperationalInsights/workspaces/{}/providers/Microsoft.SecurityInsights/incidents/{}?api-version=2025-09-01",
            self.target.subscription_id(),
            self.target.resource_group(),
            self.target.workspace_name(),
            self.incident_id
        );

        // Make the GET request
        let response = http
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Failed to get incident: {} - {}",
                status,
                body
            ));
        }

        // Parse the response
        let incident: Incident = response.json().await?;

        // Write results
        let out = InsertBatch::new(context, output_prefix);

        // Core identifiers
        if let Some(id) = &incident.id {
            out.string("id", id.clone()).await?;
        }
        if let Some(name) = &incident.name {
            out.string("name", name.clone()).await?;
        }
        if let Some(etag) = &incident.etag {
            out.string("etag", etag.clone()).await?;
        }

        // Properties
        if let Some(props) = &incident.properties {
            // Required properties
            out.string("title", props.title.clone()).await?;
            out.string("severity", format!("{:?}", props.severity)).await?;
            out.string("status", format!("{:?}", props.status)).await?;

            // Read-only properties
            if let Some(number) = props.incident_number {
                out.i64("incident_number", number as i64).await?;
            }
            if let Some(url) = &props.incident_url {
                out.string("incident_url", url.clone()).await?;
            }
            if let Some(created) = &props.created_time_utc {
                out.string("created_time_utc", created.clone()).await?;
            }
            if let Some(modified) = &props.last_modified_time_utc {
                out.string("last_modified_time_utc", modified.clone()).await?;
            }

            // Optional properties
            if let Some(desc) = &props.description {
                out.string("description", desc.clone()).await?;
            }
            if let Some(first) = &props.first_activity_time_utc {
                out.string("first_activity_time_utc", first.clone()).await?;
            }
            if let Some(last) = &props.last_activity_time_utc {
                out.string("last_activity_time_utc", last.clone()).await?;
            }
            if let Some(class) = &props.classification {
                out.string("classification", format!("{:?}", class)).await?;
            }
            if let Some(comment) = &props.classification_comment {
                out.string("classification_comment", comment.clone()).await?;
            }
            if let Some(reason) = &props.classification_reason {
                out.string("classification_reason", format!("{:?}", reason)).await?;
            }

            // Owner information
            if let Some(owner) = &props.owner {
                if let Some(object_id) = &owner.object_id {
                    out.string("owner_object_id", object_id.clone()).await?;
                }
                if let Some(email) = &owner.email {
                    out.string("owner_email", email.clone()).await?;
                }
                if let Some(assigned_to) = &owner.assigned_to {
                    out.string("owner_assigned_to", assigned_to.clone()).await?;
                }
                if let Some(upn) = &owner.user_principal_name {
                    out.string("owner_user_principal_name", upn.clone()).await?;
                }
            }

            // Additional data
            if let Some(additional) = &props.additional_data {
                if let Some(count) = additional.alerts_count {
                    out.i64("alerts_count", count as i64).await?;
                }
                if let Some(count) = additional.bookmarks_count {
                    out.i64("bookmarks_count", count as i64).await?;
                }
                if let Some(count) = additional.comments_count {
                    out.i64("comments_count", count as i64).await?;
                }
            }

            // Provider info
            if let Some(provider) = &props.provider_name {
                out.string("provider_name", provider.clone()).await?;
            }
            if let Some(provider_id) = &props.provider_incident_id {
                out.string("provider_incident_id", provider_id.clone()).await?;
            }
        }

        Ok(())
    }
}
