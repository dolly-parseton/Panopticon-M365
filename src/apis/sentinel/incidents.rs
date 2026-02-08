use crate::api_resource;
use crate::apis::ApiScope;
use oauth2::reqwest;

use super::SentinelWorkspace;
use crate::types::azure::sentinel::{raw, CreateIncident, Incident};

api_resource! {
    Incidents on SentinelWorkspace {
        list list()
            -> Vec<Incident> from raw::IncidentResponse
            at "incidents";

        get get(incident_id: &str)
            -> Incident from raw::IncidentResponse
            at "incidents/{incident_id}";

        put create_or_update(incident_id: &str)
            -> Incident from raw::IncidentResponse
            at "incidents/{incident_id}"
            with body: &CreateIncident;

        delete delete(incident_id: &str)
            at "incidents/{incident_id}";
    }
}

// Non-standard endpoints: POST-to-list patterns that don't fit the macro.
impl Incidents<'_> {
    pub async fn list_alerts(
        &self,
        incident_id: &str,
    ) -> anyhow::Result<Vec<raw::SecurityAlert>> {
        let url = self
            .scope
            .url(&format!("incidents/{incident_id}/alerts"));
        let resp: raw::AlertListResponse = self
            .scope
            .client()
            .request(self.scope.tenant_id(), reqwest::Method::POST, &url)
            .await?
            .send()
            .await?
            .json()
            .await?;
        Ok(resp.value)
    }

    pub async fn list_entities(
        &self,
        incident_id: &str,
    ) -> anyhow::Result<raw::EntityListResponse> {
        let url = self
            .scope
            .url(&format!("incidents/{incident_id}/entities"));
        let resp: raw::EntityListResponse = self
            .scope
            .client()
            .request(self.scope.tenant_id(), reqwest::Method::POST, &url)
            .await?
            .send()
            .await?
            .json()
            .await?;
        Ok(resp)
    }
}
