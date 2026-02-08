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

static RUN_PLAYBOOK_SPEC: CommandSchema = LazyLock::new(|| {
    CommandSpecBuilder::new()
        .attribute(client_id_attribute())
        .attribute(tenant_id_attribute())
        .attribute(sentinel_target_attribute())
        .attribute(incident_id_attribute())
        .attribute(
            AttributeSpecBuilder::new("logic_apps_resource_id", TypeDef::Scalar(ScalarType::String))
                .required()
                .hint("Full ARM resource ID of the Logic App playbook to run")
                .build(),
        )
        .attribute(
            AttributeSpecBuilder::new("playbook_tenant_id", TypeDef::Scalar(ScalarType::String))
                .hint("Tenant ID of the playbook (if different from current tenant)")
                .build(),
        )
        .fixed_result(
            "triggered",
            TypeDef::Scalar(ScalarType::Bool),
            Some("Whether the playbook was successfully triggered"),
            ResultKind::Data,
        )
        .build()
});

// ─── Step 2: Define the command struct ──────────────────────────────────────

pub struct RunPlaybookCommand {
    pub client_id: String,
    pub tenant_id: String,
    pub target: Target,
    pub incident_id: String,
    pub logic_apps_resource_id: String,
    pub playbook_tenant_id: Option<String>,
}

// ─── Step 3: Implement Descriptor ───────────────────────────────────────────

impl_descriptor!(RunPlaybookCommand, "RunPlaybookCommand", RUN_PLAYBOOK_SPEC);

// ─── Step 4: Implement FromAttributes ───────────────────────────────────────

impl FromAttributes for RunPlaybookCommand {
    fn from_attributes(attrs: &Attributes) -> Result<Self> {
        let client_id = attrs.get_required_string("client_id")?;
        let tenant_id = attrs.get_required_string("tenant_id")?;

        let target_str = attrs.get_required_string("target")?;
        let target = Target::try_from(target_str.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid target: {}", e))?;

        let incident_id = attrs.get_required_string("incident_id")?;
        let logic_apps_resource_id = attrs.get_required_string("logic_apps_resource_id")?;
        let playbook_tenant_id = attrs.get_optional_string("playbook_tenant_id");

        Ok(RunPlaybookCommand {
            client_id,
            tenant_id,
            target,
            incident_id,
            logic_apps_resource_id,
            playbook_tenant_id,
        })
    }
}

// ─── Step 5: Implement Executable ───────────────────────────────────────────

#[async_trait]
impl Executable for RunPlaybookCommand {
    async fn execute(&self, context: &ExecutionContext, output_prefix: &StorePath) -> Result<()> {
        let (http, token) =
            get_azure_management_token(context, &self.client_id, &self.tenant_id).await?;

        let url = self.target.incident_sub_resource_url(&self.incident_id, "runPlaybook");

        let request_body = ManualTriggerRequestBody {
            logic_apps_resource_id: Some(self.logic_apps_resource_id.clone()),
            tenant_id: self.playbook_tenant_id.clone(),
        };

        let response = http
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        check_response_success(response, "run playbook").await?;

        let out = InsertBatch::new(context, output_prefix);
        out.bool("triggered", true).await?;

        Ok(())
    }
}
