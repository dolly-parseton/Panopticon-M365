use super::types::*;
use crate::azure::common::{
    check_response_success, client_id_attribute, get_azure_management_token,
    sentinel_target_attribute, tenant_id_attribute,
};
use crate::azure::sentinel::Target;
use crate::impl_descriptor;
use panopticon_core::extend::*;
use panopticon_core::prelude::*;

// ─── Step 1: Define the CommandSchema ───────────────────────────────────────

static LIST_INCIDENTS_SPEC: CommandSchema = LazyLock::new(|| {
    CommandSpecBuilder::new()
        .attribute(client_id_attribute())
        .attribute(tenant_id_attribute())
        .attribute(sentinel_target_attribute())
        .attribute(
            AttributeSpecBuilder::new("filter", TypeDef::Scalar(ScalarType::String))
                .hint("OData filter expression (e.g., \"properties/status eq 'New'\")")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("orderby", TypeDef::Scalar(ScalarType::String))
                .hint("OData orderby expression (e.g., \"properties/createdTimeUtc desc\")")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("top", TypeDef::Scalar(ScalarType::Number))
                .hint("Maximum number of incidents to return")
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
            Some("Classification reason"),
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
        .build()
});

// ─── Step 2: Define the command struct ──────────────────────────────────────

pub struct ListIncidentsCommand {
    pub client_id: String,
    pub tenant_id: String,
    pub target: Target,
    pub filter: Option<String>,
    pub orderby: Option<String>,
    pub top: Option<i64>,
}

// ─── Step 3: Implement Descriptor ───────────────────────────────────────────

impl_descriptor!(ListIncidentsCommand, "ListIncidentsCommand", LIST_INCIDENTS_SPEC);

// ─── Step 4: Implement FromAttributes ───────────────────────────────────────

impl FromAttributes for ListIncidentsCommand {
    fn from_attributes(attrs: &Attributes) -> Result<Self> {
        let client_id = attrs.get_required_string("client_id")?;
        let tenant_id = attrs.get_required_string("tenant_id")?;

        let target_str = attrs.get_required_string("target")?;
        let target = Target::try_from(target_str.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid target: {}", e))?;

        let filter = attrs.get_optional_string("filter");
        let orderby = attrs.get_optional_string("orderby");
        let top = attrs.get_optional_i64("top");

        Ok(ListIncidentsCommand {
            client_id,
            tenant_id,
            target,
            filter,
            orderby,
            top,
        })
    }
}

// ─── Step 5: Implement Executable ───────────────────────────────────────────

#[async_trait]
impl Executable for ListIncidentsCommand {
    async fn execute(&self, context: &ExecutionContext, output_prefix: &StorePath) -> Result<()> {
        let (http, token) =
            get_azure_management_token(context, &self.client_id, &self.tenant_id).await?;

        let mut url = self.target.resource_url("incident", None);

        // Add optional query parameters (values should be URL-encoded by the caller if needed)
        if let Some(filter) = &self.filter {
            url.push_str(&format!("&$filter={}", filter));
        }
        if let Some(orderby) = &self.orderby {
            url.push_str(&format!("&$orderby={}", orderby));
        }
        if let Some(top) = self.top {
            url.push_str(&format!("&$top={}", top));
        }

        let mut row_index: usize = 0;

        loop {
            let response = http
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await?;

            let response = check_response_success(response, "list incidents").await?;
            let list: IncidentList = response.json().await?;

            if let Some(incidents) = list.value {
                for (i, incident) in incidents.iter().enumerate() {
                    let path = output_prefix.with_index(row_index + i);
                    let out = InsertBatch::new(context, &path);
                    Self::write_incident(&out, incident).await?;
                }
                row_index += incidents.len();
            }

            match list.next_link {
                Some(next) => url = next,
                None => break,
            }
        }

        Ok(())
    }
}

impl ListIncidentsCommand {
    async fn write_incident(out: &InsertBatch<'_>, incident: &Incident) -> Result<()> {
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
            out.string("title", props.title.clone()).await?;
            out.string("severity", format!("{:?}", props.severity)).await?;
            out.string("status", format!("{:?}", props.status)).await?;

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

            if let Some(provider) = &props.provider_name {
                out.string("provider_name", provider.clone()).await?;
            }
        }

        Ok(())
    }
}
