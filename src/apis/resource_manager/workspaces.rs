use crate::api_resource;

use super::ResourceManager;
use crate::types::azure::resource_manager::{raw, Workspace};

api_resource! {
    Workspaces on ResourceManager {
        list list(subscription_id: &str)
            -> Vec<Workspace> from raw::WorkspaceResponse
            at "subscriptions/{subscription_id}/providers/Microsoft.OperationalInsights/workspaces?api-version=2023-09-01";

        list list_by_resource_group(subscription_id: &str, resource_group: &str)
            -> Vec<Workspace> from raw::WorkspaceResponse
            at "subscriptions/{subscription_id}/resourcegroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces?api-version=2023-09-01";

        get get(subscription_id: &str, resource_group: &str, workspace_name: &str)
            -> Workspace from raw::WorkspaceResponse
            at "subscriptions/{subscription_id}/resourcegroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}?api-version=2023-09-01";
    }
}
