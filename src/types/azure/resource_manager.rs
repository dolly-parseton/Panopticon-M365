use std::collections::HashMap;

use super::common::{CreatedByType, SystemData};
use serde::Deserialize;

// -- Enums --

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum SubscriptionState {
    Enabled,
    Warned,
    PastDue,
    Disabled,
    Deleted,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum ProvisioningState {
    Creating,
    Succeeded,
    Failed,
    Canceled,
    Deleting,
    ProvisioningAccount,
    Updating,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum SkuName {
    Free,
    Standard,
    Premium,
    PerNode,
    PerGB2018,
    Standalone,
    CapacityReservation,
    LACluster,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum PublicNetworkAccess {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum DataIngestionStatus {
    RespectQuota,
    ForceOn,
    ForceOff,
    OverQuota,
    SubscriptionSuspended,
    ApproachingQuota,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum SpendingLimit {
    On,
    Off,
    CurrentPeriodOff,
}

// -- Domain types (flattened) --

#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: String,
    pub subscription_id: String,
    pub tenant_id: Option<String>,
    pub display_name: Option<String>,
    pub state: Option<SubscriptionState>,
    pub managed_by_tenants: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ResourceGroupInfo {
    pub id: String,
    pub name: String,
    pub location: String,
    pub provisioning_state: Option<String>,
    pub managed_by: Option<String>,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub location: String,
    pub customer_id: Option<String>,
    pub provisioning_state: Option<ProvisioningState>,
    pub sku_name: Option<SkuName>,
    pub retention_in_days: Option<i32>,
    pub daily_quota_gb: Option<f64>,
    pub public_network_access_for_ingestion: Option<PublicNetworkAccess>,
    pub public_network_access_for_query: Option<PublicNetworkAccess>,
    pub tags: HashMap<String, String>,
}

// -- From conversions --

impl From<raw::SubscriptionResponse> for Subscription {
    fn from(r: raw::SubscriptionResponse) -> Self {
        Self {
            id: r.id.unwrap_or_default(),
            subscription_id: r.subscription_id.unwrap_or_default(),
            tenant_id: r.tenant_id,
            display_name: r.display_name,
            state: r.state,
            managed_by_tenants: r
                .managed_by_tenants
                .unwrap_or_default()
                .into_iter()
                .filter_map(|m| m.tenant_id)
                .collect(),
        }
    }
}

impl From<raw::ResourceGroupResponse> for ResourceGroupInfo {
    fn from(r: raw::ResourceGroupResponse) -> Self {
        Self {
            id: r.id.unwrap_or_default(),
            name: r.name.unwrap_or_default(),
            location: r.location.unwrap_or_default(),
            provisioning_state: r.properties.and_then(|p| p.provisioning_state),
            managed_by: r.managed_by,
            tags: r.tags.unwrap_or_default(),
        }
    }
}

impl From<raw::WorkspaceResponse> for Workspace {
    fn from(r: raw::WorkspaceResponse) -> Self {
        let p = r.properties;
        Self {
            id: r.id.unwrap_or_default(),
            name: r.name.unwrap_or_default(),
            location: r.location.unwrap_or_default(),
            customer_id: p.as_ref().and_then(|p| p.customer_id.clone()),
            provisioning_state: p.as_ref().and_then(|p| p.provisioning_state.clone()),
            sku_name: p.as_ref().and_then(|p| p.sku.as_ref().map(|s| s.name.clone())),
            retention_in_days: p.as_ref().and_then(|p| p.retention_in_days),
            daily_quota_gb: p
                .as_ref()
                .and_then(|p| p.workspace_capping.as_ref().map(|c| c.daily_quota_gb)),
            public_network_access_for_ingestion: p
                .as_ref()
                .and_then(|p| p.public_network_access_for_ingestion.clone()),
            public_network_access_for_query: p
                .as_ref()
                .and_then(|p| p.public_network_access_for_query.clone()),
            tags: r.tags.unwrap_or_default(),
        }
    }
}

// -- Raw API types --

pub mod raw {
    use super::*;

    // -- Subscription types --

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SubscriptionResponse {
        pub id: Option<String>,
        pub subscription_id: Option<String>,
        pub tenant_id: Option<String>,
        pub display_name: Option<String>,
        pub state: Option<SubscriptionState>,
        pub subscription_policies: Option<SubscriptionPolicies>,
        pub authorization_source: Option<String>,
        pub managed_by_tenants: Option<Vec<ManagedByTenant>>,
        pub tags: Option<HashMap<String, String>>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SubscriptionPolicies {
        pub location_placement_id: Option<String>,
        pub quota_id: Option<String>,
        pub spending_limit: Option<SpendingLimit>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ManagedByTenant {
        pub tenant_id: Option<String>,
    }

    // -- Resource Group types --

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ResourceGroupResponse {
        pub id: Option<String>,
        pub name: Option<String>,
        #[serde(rename = "type")]
        pub resource_type: Option<String>,
        pub location: Option<String>,
        pub managed_by: Option<String>,
        pub tags: Option<HashMap<String, String>>,
        pub properties: Option<ResourceGroupProperties>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ResourceGroupProperties {
        pub provisioning_state: Option<String>,
    }

    // -- Workspace types --

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct WorkspaceResponse {
        pub id: Option<String>,
        pub name: Option<String>,
        #[serde(rename = "type")]
        pub resource_type: Option<String>,
        pub location: Option<String>,
        pub etag: Option<String>,
        pub tags: Option<HashMap<String, String>>,
        pub properties: Option<WorkspaceProperties>,
        #[serde(rename = "systemData")]
        pub system_data: Option<SystemData>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct WorkspaceProperties {
        pub customer_id: Option<String>,
        pub provisioning_state: Option<ProvisioningState>,
        pub sku: Option<WorkspaceSku>,
        pub retention_in_days: Option<i32>,
        pub workspace_capping: Option<WorkspaceCapping>,
        pub created_date: Option<String>,
        pub modified_date: Option<String>,
        pub public_network_access_for_ingestion: Option<PublicNetworkAccess>,
        pub public_network_access_for_query: Option<PublicNetworkAccess>,
        pub force_cmk_for_query: Option<bool>,
        pub default_data_collection_rule_resource_id: Option<String>,
        pub features: Option<WorkspaceFeatures>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct WorkspaceSku {
        pub name: SkuName,
        pub capacity_reservation_level: Option<i32>,
        pub last_sku_update: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct WorkspaceCapping {
        pub daily_quota_gb: f64,
        pub quota_next_reset_time: Option<String>,
        pub data_ingestion_status: Option<DataIngestionStatus>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct WorkspaceFeatures {
        pub cluster_resource_id: Option<String>,
        pub disable_local_auth: Option<bool>,
        pub enable_data_export: Option<bool>,
        pub enable_log_access_using_only_resource_permissions: Option<bool>,
        pub immediate_purge_data_on30_days: Option<bool>,
        pub unified_sentinel_billing_only: Option<bool>,
    }
}
