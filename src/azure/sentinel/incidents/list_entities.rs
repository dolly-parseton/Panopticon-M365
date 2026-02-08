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

static LIST_INCIDENT_ENTITIES_SPEC: CommandSchema = LazyLock::new(|| {
    CommandSpecBuilder::new()
        .attribute(client_id_attribute())
        .attribute(tenant_id_attribute())
        .attribute(sentinel_target_attribute())
        .attribute(incident_id_attribute())
        // Results - Entity identifiers (common to all entity types)
        .fixed_result(
            "id",
            TypeDef::Scalar(ScalarType::String),
            Some("Full ARM resource ID of the entity"),
            ResultKind::Data,
        )
        .fixed_result(
            "name",
            TypeDef::Scalar(ScalarType::String),
            Some("The entity ID"),
            ResultKind::Data,
        )
        .fixed_result(
            "kind",
            TypeDef::Scalar(ScalarType::String),
            Some("The kind of the entity (Account, Host, Ip, File, etc.)"),
            ResultKind::Data,
        )
        .fixed_result(
            "friendly_name",
            TypeDef::Scalar(ScalarType::String),
            Some("Human-readable name for the entity"),
            ResultKind::Data,
        )
        // Results - Entity-specific fields serialized as JSON
        .fixed_result(
            "properties_json",
            TypeDef::Scalar(ScalarType::String),
            Some("Entity properties serialized as JSON"),
            ResultKind::Data,
        )
        .build()
});

// ─── Step 2: Define the command struct ──────────────────────────────────────

pub struct ListIncidentEntitiesCommand {
    pub client_id: String,
    pub tenant_id: String,
    pub target: Target,
    pub incident_id: String,
}

// ─── Step 3: Implement Descriptor ───────────────────────────────────────────

impl_descriptor!(ListIncidentEntitiesCommand, "ListIncidentEntitiesCommand", LIST_INCIDENT_ENTITIES_SPEC);

// ─── Step 4: Implement FromAttributes ───────────────────────────────────────

impl FromAttributes for ListIncidentEntitiesCommand {
    fn from_attributes(attrs: &Attributes) -> Result<Self> {
        let client_id = attrs.get_required_string("client_id")?;
        let tenant_id = attrs.get_required_string("tenant_id")?;

        let target_str = attrs.get_required_string("target")?;
        let target = Target::try_from(target_str.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid target: {}", e))?;

        let incident_id = attrs.get_required_string("incident_id")?;

        Ok(ListIncidentEntitiesCommand {
            client_id,
            tenant_id,
            target,
            incident_id,
        })
    }
}

// ─── Step 5: Implement Executable ───────────────────────────────────────────

#[async_trait]
impl Executable for ListIncidentEntitiesCommand {
    async fn execute(&self, context: &ExecutionContext, output_prefix: &StorePath) -> Result<()> {
        let (http, token) =
            get_azure_management_token(context, &self.client_id, &self.tenant_id).await?;

        let url = self.target.incident_sub_resource_url(&self.incident_id, "entities");

        let response = http
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let response = check_response_success(response, "list incident entities").await?;
        let entity_response: IncidentEntitiesResponse = response.json().await?;

        if let Some(entities) = entity_response.entities {
            for (index, entity) in entities.iter().enumerate() {
                let path = output_prefix.with_index(index);
                let out = InsertBatch::new(context, &path);
                Self::write_entity(&out, entity).await?;
            }
        }

        Ok(())
    }
}

impl ListIncidentEntitiesCommand {
    async fn write_entity(out: &InsertBatch<'_>, entity: &Entity) -> Result<()> {
        match entity {
            Entity::Account(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "Account".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::Host(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "Host".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::File(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "File".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::FileHash(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "FileHash".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::AzureResource(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "AzureResource".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::CloudApplication(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "CloudApplication".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::DnsResolution(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "DnsResolution".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::Ip(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "Ip".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::Malware(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "Malware".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::Process(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "Process".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::RegistryKey(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "RegistryKey".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::RegistryValue(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "RegistryValue".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::SecurityGroup(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "SecurityGroup".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::Url(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "Url".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::IoTDevice(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "IoTDevice".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::SecurityAlert(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "SecurityAlert".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::Bookmark(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "Bookmark".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::Mailbox(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "Mailbox".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::MailCluster(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "MailCluster".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::MailMessage(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "MailMessage".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
            Entity::SubmissionMail(e) => {
                if let Some(id) = &e.id {
                    out.string("id", id.clone()).await?;
                }
                if let Some(name) = &e.name {
                    out.string("name", name.clone()).await?;
                }
                out.string("kind", "SubmissionMail".to_string()).await?;
                if let Some(props) = &e.properties {
                    if let Some(friendly_name) = &props.friendly_name {
                        out.string("friendly_name", friendly_name.clone()).await?;
                    }
                    out.string("properties_json", serde_json::to_string(props)?).await?;
                }
            }
        }

        Ok(())
    }
}
