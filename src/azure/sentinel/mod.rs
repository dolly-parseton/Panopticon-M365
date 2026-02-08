pub mod incidents;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    subscription_id: String,
    resource_group: String,
    workspace_name: String,
}

impl Target {
    /// Parses a target from a resource ID pattern string:
    /// /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();
        // Don't care if there's more bits after the workspace name, but there must be at least 8 parts to have all the required segments
        if parts.len() < 8 {
            return Err(anyhow::anyhow!(
                "Target must be in the format /subscriptions/{{subscriptionId}}/resourceGroups/{{resourceGroupName}}/providers/Microsoft.OperationalInsights/workspaces/{{workspaceName}}/"
            ));
        }
        if parts[0] != "subscriptions"
            || parts[2] != "resourceGroups"
            || parts[4] != "providers"
            || parts[5] != "Microsoft.OperationalInsights"
            || parts[6] != "workspaces"
        {
            return Err(anyhow::anyhow!(
                "Target must be in the format /subscriptions/{{subscriptionId}}/resourceGroups/{{resourceGroupName}}/providers/Microsoft.OperationalInsights/workspaces/{{workspaceName}}/"
            ));
        }
        Ok(Target {
            subscription_id: parts[1].to_string(),
            resource_group: parts[3].to_string(),
            workspace_name: parts[7].to_string(),
        })
    }

    pub fn subscription_id(&self) -> &str {
        &self.subscription_id
    }

    pub fn resource_group(&self) -> &str {
        &self.resource_group
    }

    pub fn workspace_name(&self) -> &str {
        &self.workspace_name
    }
}

impl TryFrom<&str> for Target {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

// Microsoft Sentinel REST API Operation Groups (API Version 2025-09-01)
pub enum OperationGroups {
    // Manage actions associated with alert rules
    Actions,
    // Get alert rule templates
    AlertRuleTemplates,
    // Manage alert rules
    AlertRules,
    // Manage automation rules
    AutomationRules,
    // Manage bookmarks
    Bookmarks,
    // Install or uninstall packages to the workspace
    ContentPackage,
    // Get installed packages
    ContentPackages,
    // Manage installed templates (delete, get, install)
    ContentTemplate,
    // Get all installed templates with expandable properties
    ContentTemplates,
    // Manage data connector definitions
    DataConnectorDefinitions,
    // Manage data connectors
    DataConnectors,
    // Trigger playbooks on entities
    Entities,
    // Manage comments for incidents
    IncidentComments,
    // Manage relations for incidents
    IncidentRelations,
    // Manage incident tasks
    IncidentTasks,
    // Manage incidents including alerts, bookmarks, entities, and playbooks
    Incidents,
    // Manage metadata
    Metadata,
    // List all available Azure Security Insights Resource Provider operations
    Operations,
    // Get a package by its identifier from the catalog
    ProductPackage,
    // Get all packages from the catalog
    ProductPackages,
    // Get a template by its identifier
    ProductTemplate,
    // Get all templates in the catalog
    ProductTemplates,
    // Manage Security ML Analytics settings
    SecurityMlAnalyticsSettings,
    // Manage Sentinel onboarding state
    SentinelOnboardingStates,
    // Get list of repositories metadata
    SourceControl,
    // Manage source controls
    SourceControls,
    // Manage threat intelligence indicators (create, update, delete, query, tags)
    ThreatIntelligenceIndicator,
    // Get threat intelligence indicator metrics (counts by Type, Threat Type, Source)
    ThreatIntelligenceIndicatorMetrics,
    // Get all threat intelligence indicators
    ThreatIntelligenceIndicators,
    // Manage watchlist items
    WatchlistItems,
    // Manage watchlists and bulk creation of watchlist items
    Watchlists,
}

pub struct Workspaces {
    // cache: HashMap<Target, OperationGroups>,
}
