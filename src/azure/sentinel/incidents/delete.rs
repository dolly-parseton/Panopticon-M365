use crate::azure::common::{
    check_response_success, client_id_attribute, get_azure_management_token,
    incident_id_attribute, sentinel_target_attribute, tenant_id_attribute,
};
use crate::azure::sentinel::Target;
use crate::impl_descriptor;
use panopticon_core::extend::*;
use panopticon_core::prelude::*;

// ─── Step 1: Define the CommandSchema ───────────────────────────────────────

static DELETE_INCIDENT_SPEC: CommandSchema = LazyLock::new(|| {
    CommandSpecBuilder::new()
        .attribute(client_id_attribute())
        .attribute(tenant_id_attribute())
        .attribute(sentinel_target_attribute())
        .attribute(incident_id_attribute())
        .fixed_result(
            "deleted",
            TypeDef::Scalar(ScalarType::Bool),
            Some("Whether the incident was successfully deleted"),
            ResultKind::Data,
        )
        .build()
});

// ─── Step 2: Define the command struct ──────────────────────────────────────

pub struct DeleteIncidentCommand {
    pub client_id: String,
    pub tenant_id: String,
    pub target: Target,
    pub incident_id: String,
}

// ─── Step 3: Implement Descriptor ───────────────────────────────────────────

impl_descriptor!(DeleteIncidentCommand, "DeleteIncidentCommand", DELETE_INCIDENT_SPEC);

// ─── Step 4: Implement FromAttributes ───────────────────────────────────────

impl FromAttributes for DeleteIncidentCommand {
    fn from_attributes(attrs: &Attributes) -> Result<Self> {
        let client_id = attrs.get_required_string("client_id")?;
        let tenant_id = attrs.get_required_string("tenant_id")?;

        let target_str = attrs.get_required_string("target")?;
        let target = Target::try_from(target_str.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid target: {}", e))?;

        let incident_id = attrs.get_required_string("incident_id")?;

        Ok(DeleteIncidentCommand {
            client_id,
            tenant_id,
            target,
            incident_id,
        })
    }
}

// ─── Step 5: Implement Executable ───────────────────────────────────────────

#[async_trait]
impl Executable for DeleteIncidentCommand {
    async fn execute(&self, context: &ExecutionContext, output_prefix: &StorePath) -> Result<()> {
        let (http, token) =
            get_azure_management_token(context, &self.client_id, &self.tenant_id).await?;

        let url = self.target.resource_url("incident", Some(&self.incident_id));

        let response = http
            .delete(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        check_response_success(response, "delete incident").await?;

        let out = InsertBatch::new(context, output_prefix);
        out.bool("deleted", true).await?;

        Ok(())
    }
}
