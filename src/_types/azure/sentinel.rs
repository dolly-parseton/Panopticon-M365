use super::common::{CreatedByType, ListResponse, SystemData};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// -- Shared enums across Sentinel operation groups --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IncidentStatus {
    New,
    Active,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Classification {
    Undetermined,
    TruePositive,
    BenignPositive,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClassificationReason {
    SuspiciousActivity,
    SuspiciousButExpected,
    IncorrectAlertLogic,
    InaccurateData,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OwnerType {
    Unknown,
    User,
    Group,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LabelType {
    User,
    AutoAssigned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttackTactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    Exfiltration,
    CommandAndControl,
    Impact,
    PreAttack,
    ImpairProcessControl,
    InhibitResponseFunction,
}

// -- Domain types (flattened, ergonomic) --

#[derive(Debug, Clone)]
pub struct Incident {
    pub id: String,
    pub name: String,
    pub etag: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub severity: Severity,
    pub status: IncidentStatus,
    pub incident_number: Option<i32>,
    pub incident_url: Option<String>,
    pub created_time_utc: Option<String>,
    pub last_modified_time_utc: Option<String>,
    pub first_activity_time_utc: Option<String>,
    pub last_activity_time_utc: Option<String>,
    pub classification: Option<Classification>,
    pub classification_comment: Option<String>,
    pub classification_reason: Option<ClassificationReason>,
    pub owner: Option<IncidentOwner>,
    pub labels: Vec<IncidentLabel>,
    pub provider_name: Option<String>,
    pub provider_incident_id: Option<String>,
    pub related_analytic_rule_ids: Vec<String>,
    pub alerts_count: Option<i32>,
    pub bookmarks_count: Option<i32>,
    pub comments_count: Option<i32>,
    pub alert_product_names: Vec<String>,
    pub tactics: Vec<AttackTactic>,
}

#[derive(Debug, Clone)]
pub struct IncidentOwner {
    pub object_id: Option<Uuid>,
    pub email: Option<String>,
    pub user_principal_name: Option<String>,
    pub assigned_to: Option<String>,
    pub owner_type: Option<OwnerType>,
}

#[derive(Debug, Clone)]
pub struct IncidentLabel {
    pub label_name: String,
    pub label_type: Option<LabelType>,
}

impl From<raw::IncidentResponse> for Incident {
    fn from(r: raw::IncidentResponse) -> Self {
        let p = r.properties;
        let ad = p.additional_data.unwrap_or_default();
        Self {
            id: r.id,
            name: r.name,
            etag: r.etag,
            title: p.title,
            description: p.description,
            severity: p.severity,
            status: p.status,
            incident_number: p.incident_number,
            incident_url: p.incident_url,
            created_time_utc: p.created_time_utc,
            last_modified_time_utc: p.last_modified_time_utc,
            first_activity_time_utc: p.first_activity_time_utc,
            last_activity_time_utc: p.last_activity_time_utc,
            classification: p.classification,
            classification_comment: p.classification_comment,
            classification_reason: p.classification_reason,
            owner: p.owner.map(|o| IncidentOwner {
                object_id: o.object_id,
                email: o.email,
                user_principal_name: o.user_principal_name,
                assigned_to: o.assigned_to,
                owner_type: o.owner_type,
            }),
            labels: p
                .labels
                .unwrap_or_default()
                .into_iter()
                .map(|l| IncidentLabel {
                    label_name: l.label_name,
                    label_type: l.label_type,
                })
                .collect(),
            provider_name: p.provider_name,
            provider_incident_id: p.provider_incident_id,
            related_analytic_rule_ids: p.related_analytic_rule_ids.unwrap_or_default(),
            alerts_count: ad.alerts_count,
            bookmarks_count: ad.bookmarks_count,
            comments_count: ad.comments_count,
            alert_product_names: ad.alert_product_names.unwrap_or_default(),
            tactics: ad.tactics.unwrap_or_default(),
        }
    }
}

// -- Watchlist domain types (flattened) --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceType {
    Local,
    AzureStorage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WatchlistProvisioningState {
    New,
    InProgress,
    Uploading,
    Deleting,
    Succeeded,
    Failed,
    Canceled,
}

#[derive(Debug, Clone)]
pub struct Watchlist {
    pub id: String,
    pub name: String,
    pub etag: Option<String>,
    pub watchlist_id: Option<String>,
    pub display_name: Option<String>,
    pub provider: Option<String>,
    pub source: Option<String>,
    pub source_type: Option<SourceType>,
    pub description: Option<String>,
    pub watchlist_type: Option<String>,
    pub watchlist_alias: Option<String>,
    pub items_search_key: Option<String>,
    pub is_deleted: Option<bool>,
    pub labels: Vec<String>,
    pub default_duration: Option<String>,
    pub tenant_id: Option<String>,
    pub content_type: Option<String>,
    pub number_of_lines_to_skip: Option<i32>,
    pub upload_status: Option<String>,
    pub provisioning_state: Option<WatchlistProvisioningState>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub created_by: Option<WatchlistUserInfo>,
    pub updated_by: Option<WatchlistUserInfo>,
}

#[derive(Debug, Clone)]
pub struct WatchlistUserInfo {
    pub object_id: Option<Uuid>,
    pub email: Option<String>,
    pub name: Option<String>,
}

impl From<raw::WatchlistResponse> for Watchlist {
    fn from(r: raw::WatchlistResponse) -> Self {
        let p = r.properties;
        Self {
            id: r.id,
            name: r.name,
            etag: r.etag,
            watchlist_id: p.watchlist_id,
            display_name: p.display_name,
            provider: p.provider,
            source: p.source,
            source_type: p.source_type,
            description: p.description,
            watchlist_type: p.watchlist_type,
            watchlist_alias: p.watchlist_alias,
            items_search_key: p.items_search_key,
            is_deleted: p.is_deleted,
            labels: p.labels.unwrap_or_default(),
            default_duration: p.default_duration,
            tenant_id: p.tenant_id,
            content_type: p.content_type,
            number_of_lines_to_skip: p.number_of_lines_to_skip,
            upload_status: p.upload_status,
            provisioning_state: p.provisioning_state,
            created: p.created,
            updated: p.updated,
            created_by: p.created_by.map(|u| WatchlistUserInfo {
                object_id: u.object_id,
                email: u.email,
                name: u.name,
            }),
            updated_by: p.updated_by.map(|u| WatchlistUserInfo {
                object_id: u.object_id,
                email: u.email,
                name: u.name,
            }),
        }
    }
}

// -- Request body for creating/updating watchlists --

#[derive(Debug, Clone, Serialize)]
pub struct CreateWatchlist {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    pub properties: CreateWatchlistProperties,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWatchlistProperties {
    pub display_name: String,
    pub items_search_key: String,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<SourceType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchlist_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number_of_lines_to_skip: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_duration: Option<String>,
}

// -- Watchlist Item domain types (flattened) --

#[derive(Debug, Clone)]
pub struct WatchlistItem {
    pub id: String,
    pub name: String,
    pub etag: Option<String>,
    pub watchlist_item_id: Option<String>,
    pub watchlist_item_type: Option<String>,
    pub tenant_id: Option<String>,
    pub is_deleted: Option<bool>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub created_by: Option<WatchlistUserInfo>,
    pub updated_by: Option<WatchlistUserInfo>,
    pub items_key_value: serde_json::Value,
    pub entity_mapping: Option<serde_json::Value>,
}

impl From<raw::WatchlistItemResponse> for WatchlistItem {
    fn from(r: raw::WatchlistItemResponse) -> Self {
        let p = r.properties;
        Self {
            id: r.id,
            name: r.name,
            etag: r.etag,
            watchlist_item_id: p.watchlist_item_id,
            watchlist_item_type: p.watchlist_item_type,
            tenant_id: p.tenant_id,
            is_deleted: p.is_deleted,
            created: p.created,
            updated: p.updated,
            created_by: p.created_by.map(|u| WatchlistUserInfo {
                object_id: u.object_id,
                email: u.email,
                name: u.name,
            }),
            updated_by: p.updated_by.map(|u| WatchlistUserInfo {
                object_id: u.object_id,
                email: u.email,
                name: u.name,
            }),
            items_key_value: p.items_key_value.unwrap_or(serde_json::Value::Object(Default::default())),
            entity_mapping: p.entity_mapping,
        }
    }
}

// -- Request body for creating/updating watchlist items --

#[derive(Debug, Clone, Serialize)]
pub struct CreateWatchlistItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    pub properties: CreateWatchlistItemProperties,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWatchlistItemProperties {
    pub items_key_value: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_mapping: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchlist_item_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchlist_item_type: Option<String>,
}

// -- Request body for creating/updating incidents --

#[derive(Debug, Clone, Serialize)]
pub struct CreateIncident {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    pub properties: CreateIncidentProperties,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateIncidentProperties {
    pub title: String,
    pub severity: Severity,
    pub status: IncidentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_activity_time_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity_time_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<raw::IncidentOwnerInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<Classification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification_comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification_reason: Option<ClassificationReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<raw::IncidentLabelInfo>>,
}

// -- Raw API types (mirror Azure JSON exactly) --

pub mod raw {
    use super::*;

    #[derive(Debug, Clone, Deserialize)]
    pub struct IncidentResponse {
        pub id: String,
        pub name: String,
        #[serde(rename = "type")]
        pub resource_type: Option<String>,
        pub etag: Option<String>,
        pub properties: IncidentProperties,
        #[serde(rename = "systemData")]
        pub system_data: Option<SystemData>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct IncidentProperties {
        pub title: String,
        pub severity: Severity,
        pub status: IncidentStatus,
        pub description: Option<String>,
        pub incident_number: Option<i32>,
        pub incident_url: Option<String>,
        pub created_time_utc: Option<String>,
        pub last_modified_time_utc: Option<String>,
        pub first_activity_time_utc: Option<String>,
        pub last_activity_time_utc: Option<String>,
        pub classification: Option<Classification>,
        pub classification_comment: Option<String>,
        pub classification_reason: Option<ClassificationReason>,
        pub owner: Option<IncidentOwnerInfo>,
        pub labels: Option<Vec<IncidentLabelInfo>>,
        pub provider_name: Option<String>,
        pub provider_incident_id: Option<String>,
        pub related_analytic_rule_ids: Option<Vec<String>>,
        pub additional_data: Option<IncidentAdditionalData>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct IncidentOwnerInfo {
        pub object_id: Option<Uuid>,
        pub email: Option<String>,
        pub user_principal_name: Option<String>,
        pub assigned_to: Option<String>,
        pub owner_type: Option<OwnerType>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct IncidentLabelInfo {
        pub label_name: String,
        pub label_type: Option<LabelType>,
    }

    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct IncidentAdditionalData {
        pub alerts_count: Option<i32>,
        pub bookmarks_count: Option<i32>,
        pub comments_count: Option<i32>,
        pub alert_product_names: Option<Vec<String>>,
        pub tactics: Option<Vec<AttackTactic>>,
        pub provider_incident_url: Option<String>,
    }

    // -- Watchlist types --

    #[derive(Debug, Clone, Deserialize)]
    pub struct WatchlistResponse {
        pub id: String,
        pub name: String,
        #[serde(rename = "type")]
        pub resource_type: Option<String>,
        pub etag: Option<String>,
        pub properties: WatchlistProperties,
        #[serde(rename = "systemData")]
        pub system_data: Option<SystemData>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct WatchlistProperties {
        pub watchlist_id: Option<String>,
        pub display_name: Option<String>,
        pub provider: Option<String>,
        pub source: Option<String>,
        pub source_type: Option<SourceType>,
        pub description: Option<String>,
        pub watchlist_type: Option<String>,
        pub watchlist_alias: Option<String>,
        pub items_search_key: Option<String>,
        pub is_deleted: Option<bool>,
        pub labels: Option<Vec<String>>,
        pub default_duration: Option<String>,
        pub tenant_id: Option<String>,
        pub content_type: Option<String>,
        pub number_of_lines_to_skip: Option<i32>,
        pub raw_content: Option<String>,
        pub upload_status: Option<String>,
        pub provisioning_state: Option<WatchlistProvisioningState>,
        pub created: Option<String>,
        pub updated: Option<String>,
        pub created_by: Option<WatchlistUserInfoRaw>,
        pub updated_by: Option<WatchlistUserInfoRaw>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct WatchlistUserInfoRaw {
        pub object_id: Option<Uuid>,
        pub email: Option<String>,
        pub name: Option<String>,
    }

    // -- Watchlist Item types --

    #[derive(Debug, Clone, Deserialize)]
    pub struct WatchlistItemResponse {
        pub id: String,
        pub name: String,
        #[serde(rename = "type")]
        pub resource_type: Option<String>,
        pub etag: Option<String>,
        pub properties: WatchlistItemProperties,
        #[serde(rename = "systemData")]
        pub system_data: Option<SystemData>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct WatchlistItemProperties {
        pub watchlist_item_id: Option<String>,
        pub watchlist_item_type: Option<String>,
        pub tenant_id: Option<String>,
        pub is_deleted: Option<bool>,
        pub created: Option<String>,
        pub updated: Option<String>,
        pub created_by: Option<WatchlistUserInfoRaw>,
        pub updated_by: Option<WatchlistUserInfoRaw>,
        pub items_key_value: Option<serde_json::Value>,
        pub entity_mapping: Option<serde_json::Value>,
    }

    // -- Alert types (returned by list_alerts) --

    #[derive(Debug, Clone, Deserialize)]
    pub struct AlertListResponse {
        pub value: Vec<SecurityAlert>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SecurityAlert {
        pub id: Option<String>,
        pub name: Option<String>,
        #[serde(rename = "type")]
        pub resource_type: Option<String>,
        pub kind: Option<String>,
        pub properties: Option<SecurityAlertProperties>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SecurityAlertProperties {
        pub system_alert_id: Option<String>,
        pub alert_display_name: Option<String>,
        pub alert_type: Option<String>,
        pub alert_link: Option<String>,
        pub description: Option<String>,
        pub compromised_entity: Option<String>,
        pub vendor_name: Option<String>,
        pub product_name: Option<String>,
        pub severity: Option<Severity>,
        pub status: Option<String>,
        pub tactics: Option<Vec<AttackTactic>>,
        pub start_time_utc: Option<String>,
        pub end_time_utc: Option<String>,
        pub time_generated: Option<String>,
        pub friendly_name: Option<String>,
    }

    // -- Entity types (returned by list_entities) --

    #[derive(Debug, Clone, Deserialize)]
    pub struct EntityListResponse {
        pub entities: Vec<Entity>,
        #[serde(rename = "metaData")]
        pub metadata: Option<Vec<EntityMetadata>>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct Entity {
        pub id: Option<String>,
        pub name: Option<String>,
        #[serde(rename = "type")]
        pub resource_type: Option<String>,
        pub kind: Option<String>,
        pub properties: Option<serde_json::Value>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct EntityMetadata {
        pub entity_kind: Option<String>,
        pub count: Option<i32>,
    }
}
