use crate::api_resource;

use super::ResourceManager;
use crate::types::azure::resource_manager::{raw, ResourceGroupInfo};

api_resource! {
    ResourceGroups on ResourceManager {
        list list(subscription_id: &str)
            -> Vec<ResourceGroupInfo> from raw::ResourceGroupResponse
            at "subscriptions/{subscription_id}/resourcegroups?api-version=2024-11-01";
    }
}
