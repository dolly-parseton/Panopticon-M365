use super::types::*;
use crate::azure::common::{
    check_response_success, client_id_attribute, get_azure_management_token,
    incident_id_attribute, sentinel_target_attribute, tenant_id_attribute,
};
use crate::azure::sentinel::Target;
use crate::impl_descriptor;
use panopticon_core::extend::*;
use panopticon_core::prelude::*;

// ─── Step 1: Define the CommandSchema ───────────────────────────────────────

static CREATE_INCIDENT_SPEC: CommandSchema = LazyLock::new(|| {
    CommandSpecBuilder::new()
        .attribute(client_id_attribute())
        .attribute(tenant_id_attribute())
        .attribute(sentinel_target_attribute())
        .attribute(incident_id_attribute())
        .attribute(
            AttributeSpecBuilder::new("title", TypeDef::Scalar(ScalarType::String))
                .required()
                .hint("The title of the incident")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("severity", TypeDef::Scalar(ScalarType::String))
                .required()
                .hint("Incident severity: High, Medium, Low, or Informational")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("status", TypeDef::Scalar(ScalarType::String))
                .required()
                .hint("Incident status: New, Active, or Closed")
                .build(),
        )
        // Optional attributes
        .attribute(
            AttributeSpecBuilder::new("etag", TypeDef::Scalar(ScalarType::String))
                .hint("Etag of the Azure resource")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("description", TypeDef::Scalar(ScalarType::String))
                .hint("The description of the incident")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("classification", TypeDef::Scalar(ScalarType::String))
                .hint("Classification: Undetermined, TruePositive, BenignPositive, or FalsePositive")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("classification_comment", TypeDef::Scalar(ScalarType::String))
                .hint("Describes the reason the incident was closed")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("classification_reason", TypeDef::Scalar(ScalarType::String))
                .hint("Classification reason: SuspiciousActivity, SuspiciousButExpected, IncorrectAlertLogic, or InaccurateData")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("first_activity_time_utc", TypeDef::Scalar(ScalarType::String))
                .hint("The time of the first activity in the incident (ISO 8601)")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("last_activity_time_utc", TypeDef::Scalar(ScalarType::String))
                .hint("The time of the last activity in the incident (ISO 8601)")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("owner_object_id", TypeDef::Scalar(ScalarType::String))
                .hint("Azure AD object ID of the incident owner")
                .build(),
        )
        // Results
        .fixed_result(
            "incident_id",
            TypeDef::Scalar(ScalarType::String),
            Some("The ID of the created/updated incident"),
            ResultKind::Data,
        )
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
        .build()
});

// ─── Step 2: Define the command struct ──────────────────────────────────────

pub struct CreateIncidentCommand {
    // Auth
    pub client_id: String,
    pub tenant_id: String,
    // Target
    pub target: Target,
    pub incident_id: String,
    // Required fields
    pub title: String,
    pub severity: IncidentSeverity,
    pub status: IncidentStatus,
    // Optional fields
    pub etag: Option<String>,
    pub description: Option<String>,
    pub classification: Option<IncidentClassification>,
    pub classification_comment: Option<String>,
    pub classification_reason: Option<IncidentClassificationReason>,
    pub first_activity_time_utc: Option<String>,
    pub last_activity_time_utc: Option<String>,
    pub owner_object_id: Option<String>,
}

// ─── Step 3: Implement Descriptor ───────────────────────────────────────────

impl_descriptor!(CreateIncidentCommand, "CreateIncidentCommand", CREATE_INCIDENT_SPEC);

// ─── Step 4: Implement FromAttributes ───────────────────────────────────────

impl FromAttributes for CreateIncidentCommand {
    fn from_attributes(attrs: &Attributes) -> Result<Self> {
        let client_id = attrs.get_required_string("client_id")?;
        let tenant_id = attrs.get_required_string("tenant_id")?;

        let target_str = attrs.get_required_string("target")?;
        let target = Target::try_from(target_str.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid target: {}", e))?;

        let incident_id = attrs.get_required_string("incident_id")?;
        let title = attrs.get_required_string("title")?;

        let severity_str = attrs.get_required_string("severity")?;
        let severity = parse_incident_severity(&severity_str)?;

        let status_str = attrs.get_required_string("status")?;
        let status = parse_incident_status(&status_str)?;

        let etag = attrs.get_optional_string("etag");
        let description = attrs.get_optional_string("description");

        let classification = attrs
            .get_optional_string("classification")
            .map(|s| parse_incident_classification(&s))
            .transpose()?;

        let classification_comment = attrs.get_optional_string("classification_comment");

        let classification_reason = attrs
            .get_optional_string("classification_reason")
            .map(|s| parse_incident_classification_reason(&s))
            .transpose()?;

        let first_activity_time_utc = attrs.get_optional_string("first_activity_time_utc");
        let last_activity_time_utc = attrs.get_optional_string("last_activity_time_utc");
        let owner_object_id = attrs.get_optional_string("owner_object_id");

        Ok(CreateIncidentCommand {
            client_id,
            tenant_id,
            target,
            incident_id,
            title,
            severity,
            status,
            etag,
            description,
            classification,
            classification_comment,
            classification_reason,
            first_activity_time_utc,
            last_activity_time_utc,
            owner_object_id,
        })
    }
}

// ─── Step 5: Implement Executable ───────────────────────────────────────────

#[async_trait]
impl Executable for CreateIncidentCommand {
    async fn execute(&self, context: &ExecutionContext, output_prefix: &StorePath) -> Result<()> {
        let (http, token) =
            get_azure_management_token(context, &self.client_id, &self.tenant_id).await?;

        let request_body = self.build_request_body();
        let url = self.target.resource_url("incident", Some(&self.incident_id));

        let response = http
            .put(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        let response = check_response_success(response, "create/update incident").await?;
        let incident: Incident = response.json().await?;

        // Write results
        let out = InsertBatch::new(context, output_prefix);

        if let Some(name) = &incident.name {
            out.string("incident_id", name.clone()).await?;
        }

        if let Some(props) = &incident.properties {
            if let Some(number) = props.incident_number {
                out.i64("incident_number", number as i64).await?;
            }
            if let Some(url) = &props.incident_url {
                out.string("incident_url", url.clone()).await?;
            }
        }

        Ok(())
    }
}

// ─── Helper methods ─────────────────────────────────────────────────────────

impl CreateIncidentCommand {
    fn build_request_body(&self) -> serde_json::Value {
        let mut properties = serde_json::json!({
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
        });

        if let Some(desc) = &self.description {
            properties["description"] = serde_json::json!(desc);
        }
        if let Some(class) = &self.classification {
            properties["classification"] = serde_json::json!(class);
        }
        if let Some(comment) = &self.classification_comment {
            properties["classificationComment"] = serde_json::json!(comment);
        }
        if let Some(reason) = &self.classification_reason {
            properties["classificationReason"] = serde_json::json!(reason);
        }
        if let Some(first) = &self.first_activity_time_utc {
            properties["firstActivityTimeUtc"] = serde_json::json!(first);
        }
        if let Some(last) = &self.last_activity_time_utc {
            properties["lastActivityTimeUtc"] = serde_json::json!(last);
        }
        if let Some(owner_id) = &self.owner_object_id {
            properties["owner"] = serde_json::json!({
                "objectId": owner_id
            });
        }

        let mut body = serde_json::json!({
            "properties": properties
        });

        if let Some(etag) = &self.etag {
            body["etag"] = serde_json::json!(etag);
        }

        body
    }
}

// ─── Parsing helpers ────────────────────────────────────────────────────────
