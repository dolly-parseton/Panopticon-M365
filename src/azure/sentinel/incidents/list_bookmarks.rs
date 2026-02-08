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

static LIST_INCIDENT_BOOKMARKS_SPEC: CommandSchema = LazyLock::new(|| {
    CommandSpecBuilder::new()
        .attribute(client_id_attribute())
        .attribute(tenant_id_attribute())
        .attribute(sentinel_target_attribute())
        .attribute(incident_id_attribute())
        // Results - Core identifiers
        .fixed_result(
            "id",
            TypeDef::Scalar(ScalarType::String),
            Some("Full ARM resource ID of the bookmark"),
            ResultKind::Data,
        )
        .fixed_result(
            "name",
            TypeDef::Scalar(ScalarType::String),
            Some("The bookmark ID"),
            ResultKind::Data,
        )
        .fixed_result(
            "kind",
            TypeDef::Scalar(ScalarType::String),
            Some("The kind of the entity (Bookmark)"),
            ResultKind::Data,
        )
        // Results - Bookmark properties
        .fixed_result(
            "display_name",
            TypeDef::Scalar(ScalarType::String),
            Some("Display name of the bookmark"),
            ResultKind::Data,
        )
        .fixed_result(
            "created",
            TypeDef::Scalar(ScalarType::String),
            Some("Time the bookmark was created (ISO 8601)"),
            ResultKind::Data,
        )
        .fixed_result(
            "created_by_object_id",
            TypeDef::Scalar(ScalarType::String),
            Some("Object ID of the user who created the bookmark"),
            ResultKind::Data,
        )
        .fixed_result(
            "created_by_name",
            TypeDef::Scalar(ScalarType::String),
            Some("Name of the user who created the bookmark"),
            ResultKind::Data,
        )
        .fixed_result(
            "created_by_email",
            TypeDef::Scalar(ScalarType::String),
            Some("Email of the user who created the bookmark"),
            ResultKind::Data,
        )
        .fixed_result(
            "updated",
            TypeDef::Scalar(ScalarType::String),
            Some("Time the bookmark was last updated (ISO 8601)"),
            ResultKind::Data,
        )
        .fixed_result(
            "updated_by_object_id",
            TypeDef::Scalar(ScalarType::String),
            Some("Object ID of the user who last updated the bookmark"),
            ResultKind::Data,
        )
        .fixed_result(
            "updated_by_name",
            TypeDef::Scalar(ScalarType::String),
            Some("Name of the user who last updated the bookmark"),
            ResultKind::Data,
        )
        .fixed_result(
            "event_time",
            TypeDef::Scalar(ScalarType::String),
            Some("Event time of the bookmark (ISO 8601)"),
            ResultKind::Data,
        )
        .fixed_result(
            "notes",
            TypeDef::Scalar(ScalarType::String),
            Some("Notes associated with the bookmark"),
            ResultKind::Data,
        )
        .fixed_result(
            "query",
            TypeDef::Scalar(ScalarType::String),
            Some("The query that generated the bookmark"),
            ResultKind::Data,
        )
        .fixed_result(
            "query_result",
            TypeDef::Scalar(ScalarType::String),
            Some("The query result"),
            ResultKind::Data,
        )
        .fixed_result(
            "incident_id",
            TypeDef::Scalar(ScalarType::String),
            Some("Related incident ID"),
            ResultKind::Data,
        )
        .fixed_result(
            "incident_severity",
            TypeDef::Scalar(ScalarType::String),
            Some("Related incident severity"),
            ResultKind::Data,
        )
        .fixed_result(
            "incident_title",
            TypeDef::Scalar(ScalarType::String),
            Some("Related incident title"),
            ResultKind::Data,
        )
        .build()
});

// ─── Step 2: Define the command struct ──────────────────────────────────────

pub struct ListIncidentBookmarksCommand {
    pub client_id: String,
    pub tenant_id: String,
    pub target: Target,
    pub incident_id: String,
}

// ─── Step 3: Implement Descriptor ───────────────────────────────────────────

impl_descriptor!(ListIncidentBookmarksCommand, "ListIncidentBookmarksCommand", LIST_INCIDENT_BOOKMARKS_SPEC);

// ─── Step 4: Implement FromAttributes ───────────────────────────────────────

impl FromAttributes for ListIncidentBookmarksCommand {
    fn from_attributes(attrs: &Attributes) -> Result<Self> {
        let client_id = attrs.get_required_string("client_id")?;
        let tenant_id = attrs.get_required_string("tenant_id")?;

        let target_str = attrs.get_required_string("target")?;
        let target = Target::try_from(target_str.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid target: {}", e))?;

        let incident_id = attrs.get_required_string("incident_id")?;

        Ok(ListIncidentBookmarksCommand {
            client_id,
            tenant_id,
            target,
            incident_id,
        })
    }
}

// ─── Step 5: Implement Executable ───────────────────────────────────────────

#[async_trait]
impl Executable for ListIncidentBookmarksCommand {
    async fn execute(&self, context: &ExecutionContext, output_prefix: &StorePath) -> Result<()> {
        let (http, token) =
            get_azure_management_token(context, &self.client_id, &self.tenant_id).await?;

        let url = self.target.incident_sub_resource_url(&self.incident_id, "bookmarks");

        let response = http
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let response = check_response_success(response, "list incident bookmarks").await?;
        let bookmark_list: IncidentBookmarkList = response.json().await?;

        for (index, bookmark) in bookmark_list.value.iter().enumerate() {
            let path = output_prefix.with_index(index);
            let out = InsertBatch::new(context, &path);
            Self::write_bookmark(&out, bookmark).await?;
        }

        Ok(())
    }
}

impl ListIncidentBookmarksCommand {
    async fn write_bookmark(out: &InsertBatch<'_>, bookmark: &HuntingBookmark) -> Result<()> {
        out.string("id", bookmark.id.clone()).await?;
        out.string("name", bookmark.name.clone()).await?;
        out.string("kind", bookmark.kind.clone()).await?;

        if let Some(props) = &bookmark.properties {
            if let Some(display_name) = &props.display_name {
                out.string("display_name", display_name.clone()).await?;
            }
            if let Some(created) = &props.created {
                out.string("created", created.clone()).await?;
            }
            if let Some(created_by) = &props.created_by {
                if let Some(object_id) = &created_by.object_id {
                    out.string("created_by_object_id", object_id.clone()).await?;
                }
                if let Some(name) = &created_by.name {
                    out.string("created_by_name", name.clone()).await?;
                }
                if let Some(email) = &created_by.email {
                    out.string("created_by_email", email.clone()).await?;
                }
            }
            if let Some(updated) = &props.updated {
                out.string("updated", updated.clone()).await?;
            }
            if let Some(updated_by) = &props.updated_by {
                if let Some(object_id) = &updated_by.object_id {
                    out.string("updated_by_object_id", object_id.clone()).await?;
                }
                if let Some(name) = &updated_by.name {
                    out.string("updated_by_name", name.clone()).await?;
                }
            }
            if let Some(event_time) = &props.event_time {
                out.string("event_time", event_time.clone()).await?;
            }
            if let Some(notes) = &props.notes {
                out.string("notes", notes.clone()).await?;
            }
            if let Some(query) = &props.query {
                out.string("query", query.clone()).await?;
            }
            if let Some(query_result) = &props.query_result {
                out.string("query_result", query_result.clone()).await?;
            }
            if let Some(incident_info) = &props.incident_info {
                if let Some(incident_id) = &incident_info.incident_id {
                    out.string("incident_id", incident_id.clone()).await?;
                }
                if let Some(severity) = &incident_info.severity {
                    out.string("incident_severity", format!("{:?}", severity)).await?;
                }
                if let Some(title) = &incident_info.title {
                    out.string("incident_title", title.clone()).await?;
                }
            }
        }

        Ok(())
    }
}
