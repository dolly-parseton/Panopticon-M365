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

static LIST_INCIDENT_ALERTS_SPEC: CommandSchema = LazyLock::new(|| {
    CommandSpecBuilder::new()
        .attribute(client_id_attribute())
        .attribute(tenant_id_attribute())
        .attribute(sentinel_target_attribute())
        .attribute(incident_id_attribute())
        // Results - Core identifiers
        .fixed_result(
            "id",
            TypeDef::Scalar(ScalarType::String),
            Some("Full ARM resource ID of the alert"),
            ResultKind::Data,
        )
        .fixed_result(
            "name",
            TypeDef::Scalar(ScalarType::String),
            Some("The alert ID"),
            ResultKind::Data,
        )
        .fixed_result(
            "kind",
            TypeDef::Scalar(ScalarType::String),
            Some("The kind of the entity (SecurityAlert)"),
            ResultKind::Data,
        )
        // Results - Alert properties
        .fixed_result(
            "system_alert_id",
            TypeDef::Scalar(ScalarType::String),
            Some("System generated alert ID"),
            ResultKind::Data,
        )
        .fixed_result(
            "alert_display_name",
            TypeDef::Scalar(ScalarType::String),
            Some("Display name of the alert"),
            ResultKind::Data,
        )
        .fixed_result(
            "alert_type",
            TypeDef::Scalar(ScalarType::String),
            Some("The type of the alert"),
            ResultKind::Data,
        )
        .fixed_result(
            "severity",
            TypeDef::Scalar(ScalarType::String),
            Some("Alert severity: High, Medium, Low, or Informational"),
            ResultKind::Data,
        )
        .fixed_result(
            "status",
            TypeDef::Scalar(ScalarType::String),
            Some("Alert status"),
            ResultKind::Data,
        )
        .fixed_result(
            "description",
            TypeDef::Scalar(ScalarType::String),
            Some("Description of the alert"),
            ResultKind::Data,
        )
        .fixed_result(
            "compromised_entity",
            TypeDef::Scalar(ScalarType::String),
            Some("The compromised entity"),
            ResultKind::Data,
        )
        .fixed_result(
            "confidence_level",
            TypeDef::Scalar(ScalarType::String),
            Some("Confidence level of the alert"),
            ResultKind::Data,
        )
        .fixed_result(
            "confidence_score",
            TypeDef::Scalar(ScalarType::Number),
            Some("Confidence score of the alert"),
            ResultKind::Data,
        )
        .fixed_result(
            "start_time_utc",
            TypeDef::Scalar(ScalarType::String),
            Some("Start time of the alert activity (ISO 8601)"),
            ResultKind::Data,
        )
        .fixed_result(
            "end_time_utc",
            TypeDef::Scalar(ScalarType::String),
            Some("End time of the alert activity (ISO 8601)"),
            ResultKind::Data,
        )
        .fixed_result(
            "time_generated",
            TypeDef::Scalar(ScalarType::String),
            Some("Time the alert was generated (ISO 8601)"),
            ResultKind::Data,
        )
        .fixed_result(
            "product_name",
            TypeDef::Scalar(ScalarType::String),
            Some("Product name that generated the alert"),
            ResultKind::Data,
        )
        .fixed_result(
            "vendor_name",
            TypeDef::Scalar(ScalarType::String),
            Some("Vendor name that generated the alert"),
            ResultKind::Data,
        )
        .fixed_result(
            "alert_link",
            TypeDef::Scalar(ScalarType::String),
            Some("Link to the alert in the provider portal"),
            ResultKind::Data,
        )
        .fixed_result(
            "intent",
            TypeDef::Scalar(ScalarType::String),
            Some("Kill chain intent of the alert"),
            ResultKind::Data,
        )
        .fixed_result(
            "provider_alert_id",
            TypeDef::Scalar(ScalarType::String),
            Some("Provider's alert ID"),
            ResultKind::Data,
        )
        .build()
});

// ─── Step 2: Define the command struct ──────────────────────────────────────

pub struct ListIncidentAlertsCommand {
    pub client_id: String,
    pub tenant_id: String,
    pub target: Target,
    pub incident_id: String,
}

// ─── Step 3: Implement Descriptor ───────────────────────────────────────────

impl_descriptor!(ListIncidentAlertsCommand, "ListIncidentAlertsCommand", LIST_INCIDENT_ALERTS_SPEC);

// ─── Step 4: Implement FromAttributes ───────────────────────────────────────

impl FromAttributes for ListIncidentAlertsCommand {
    fn from_attributes(attrs: &Attributes) -> Result<Self> {
        let client_id = attrs.get_required_string("client_id")?;
        let tenant_id = attrs.get_required_string("tenant_id")?;

        let target_str = attrs.get_required_string("target")?;
        let target = Target::try_from(target_str.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid target: {}", e))?;

        let incident_id = attrs.get_required_string("incident_id")?;

        Ok(ListIncidentAlertsCommand {
            client_id,
            tenant_id,
            target,
            incident_id,
        })
    }
}

// ─── Step 5: Implement Executable ───────────────────────────────────────────

#[async_trait]
impl Executable for ListIncidentAlertsCommand {
    async fn execute(&self, context: &ExecutionContext, output_prefix: &StorePath) -> Result<()> {
        let (http, token) =
            get_azure_management_token(context, &self.client_id, &self.tenant_id).await?;

        let url = self.target.incident_sub_resource_url(&self.incident_id, "alerts");

        let response = http
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let response = check_response_success(response, "list incident alerts").await?;
        let alert_list: IncidentAlertList = response.json().await?;

        for (index, alert) in alert_list.value.iter().enumerate() {
            let path = output_prefix.with_index(index);
            let out = InsertBatch::new(context, &path);
            Self::write_alert(&out, alert).await?;
        }

        Ok(())
    }
}

impl ListIncidentAlertsCommand {
    async fn write_alert(out: &InsertBatch<'_>, alert: &SecurityAlert) -> Result<()> {
        out.string("id", alert.id.clone()).await?;
        out.string("name", alert.name.clone()).await?;
        out.string("kind", alert.kind.clone()).await?;

        if let Some(props) = &alert.properties {
            if let Some(system_alert_id) = &props.system_alert_id {
                out.string("system_alert_id", system_alert_id.clone()).await?;
            }
            if let Some(display_name) = &props.alert_display_name {
                out.string("alert_display_name", display_name.clone()).await?;
            }
            if let Some(alert_type) = &props.alert_type {
                out.string("alert_type", alert_type.clone()).await?;
            }
            if let Some(severity) = &props.severity {
                out.string("severity", format!("{:?}", severity)).await?;
            }
            if let Some(status) = &props.status {
                out.string("status", format!("{:?}", status)).await?;
            }
            if let Some(description) = &props.description {
                out.string("description", description.clone()).await?;
            }
            if let Some(entity) = &props.compromised_entity {
                out.string("compromised_entity", entity.clone()).await?;
            }
            if let Some(level) = &props.confidence_level {
                out.string("confidence_level", format!("{:?}", level)).await?;
            }
            if let Some(score) = props.confidence_score {
                out.f64("confidence_score", score).await?;
            }
            if let Some(start) = &props.start_time_utc {
                out.string("start_time_utc", start.clone()).await?;
            }
            if let Some(end) = &props.end_time_utc {
                out.string("end_time_utc", end.clone()).await?;
            }
            if let Some(generated) = &props.time_generated {
                out.string("time_generated", generated.clone()).await?;
            }
            if let Some(product) = &props.product_name {
                out.string("product_name", product.clone()).await?;
            }
            if let Some(vendor) = &props.vendor_name {
                out.string("vendor_name", vendor.clone()).await?;
            }
            if let Some(link) = &props.alert_link {
                out.string("alert_link", link.clone()).await?;
            }
            if let Some(intent) = &props.intent {
                out.string("intent", format!("{:?}", intent)).await?;
            }
            if let Some(provider_id) = &props.provider_alert_id {
                out.string("provider_alert_id", provider_id.clone()).await?;
            }
        }

        Ok(())
    }
}
