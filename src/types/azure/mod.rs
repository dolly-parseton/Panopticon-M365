pub mod common;
pub mod log_analytics;
pub mod resource_manager;
pub mod sentinel;

use panopticon_core::extend::Result;
use uuid::Uuid;

/*
    Source: https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-resource#return-value-5
    ```
    The resource ID is returned in different formats at different scopes:
        Resource group scope:

            /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}

        Subscription scope:

            /subscriptions/{subscriptionId}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}

        Management group or tenant scope:

            /providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    ```

    Types:
    * ResourceGroup - validated resource group name
    * ProviderNamespace - validated provider namespace
    * ResourceId - enum of the three possible resource ID formats at different scopes
*/
pub enum ResourceId {
    ResourceGroup {
        subscription_id: Uuid,
        resource_group_name: ResourceGroup,
        provider_namespace: ProviderNamespace,
        resource_type: String,
        resource_name: String,
    },
    Subscription {
        subscription_id: Uuid,
        provider_namespace: ProviderNamespace,
        resource_type: String,
        resource_name: String,
    },
    ManagementGroupOrTenant {
        provider_namespace: ProviderNamespace,
        resource_type: String,
        resource_name: String,
    },
}

pub struct ProviderNamespace(String, String);

impl ProviderNamespace {
    pub fn try_from<T: Into<String>>(value: T) -> Result<Self> {
        /*
            As far as I can tell it's just a prefix.suffix format with alphanumerics and a dot between. (Microsoft.Compute, Microsoft.Security, etc.)
        */
        let s = value.into();
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Provider Namespace must be in the format 'prefix.suffix'"
            ));
        }
        for part in &parts {
            if part.is_empty() || !part.chars().all(|c| c.is_alphanumeric()) {
                return Err(anyhow::anyhow!(
                    "Provider Namespace parts must be alphanumerics only"
                ));
            }
        }
        Ok(ProviderNamespace(
            parts[0].to_string(),
            parts[1].to_string(),
        ))
    }
}
pub struct ResourceGroup {
    name: String,
}

impl ResourceGroup {
    pub fn try_from<T: Into<String>>(value: T) -> Result<Self> {
        /*
            As far as I can tell there's only a few rules:
            * 1 to 90 characters
            * Alphanumerics, underscores, parentheses, hyphens, periods
            * Can't end with period
        */
        let s = value.into();
        let len = s.len();
        if len < 1 || len > 90 {
            return Err(anyhow::anyhow!(
                "Resource Group name must be between 1 and 90 characters"
            ));
        }
        if s.ends_with('.') {
            return Err(anyhow::anyhow!(
                "Resource Group name cannot end with a period"
            ));
        }
        if !s
            .chars()
            .all(|c| c.is_alphanumeric() || "_().-".contains(c))
        {
            return Err(anyhow::anyhow!(
                "Resource Group name contains invalid characters"
            ));
        }
        Ok(ResourceGroup { name: s })
    }
}
