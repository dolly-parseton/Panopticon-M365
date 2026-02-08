use super::types::*;
use crate::azure::common::{
    check_response_success, client_id_attribute, get_log_analytics_token, query_attribute,
    tenant_id_attribute, timespan_attribute, workspace_id_attribute,
};
use crate::azure::log_analytics::Target;
use crate::impl_descriptor;
use anyhow::Result;
use panopticon_core::extend::*;
use panopticon_core::prelude::*;

static GET_QUERY_SPEC: CommandSchema = LazyLock::new(|| {
    CommandSpecBuilder::new()
        .attribute(client_id_attribute())
        .attribute(tenant_id_attribute())
        .attribute(workspace_id_attribute())
        .attribute(query_attribute())
        .attribute(timespan_attribute())
        .build()
});

pub struct GetQueryCommand {
    pub client_id: String,
    pub tenant_id: String,
    pub target: Target,
    pub query: String,
    pub timespan: Option<String>,
}

impl_descriptor!(GetQueryCommand, "GetQueryCommand", GET_QUERY_SPEC);

impl FromAttributes for GetQueryCommand {
    fn from_attributes(attrs: &Attributes) -> Result<Self> {
        let client_id = attrs.get_required_string("client_id")?;
        let tenant_id = attrs.get_required_string("tenant_id")?;

        let workspace_id = attrs.get_required_string("workspace_id")?;
        let target = Target::try_from(workspace_id.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid workspace_id: {}", e))?;

        let query = attrs.get_required_string("query")?;
        let timespan = attrs.get_optional_string("timespan");

        Ok(GetQueryCommand {
            client_id,
            tenant_id,
            target,
            query,
            timespan,
        })
    }
}

#[async_trait]
impl Executable for GetQueryCommand {
    async fn execute(&self, context: &ExecutionContext, output_prefix: &StorePath) -> Result<()> {
        let (http, token) =
            get_log_analytics_token(context, &self.client_id, &self.tenant_id).await?;

        let mut request = http
            .get(self.target.query_url())
            .header("Authorization", format!("Bearer {}", token))
            .query(&[("query", &self.query)]);

        if let Some(timespan) = &self.timespan {
            request = request.query(&[("timespan", timespan)]);
        }

        let response = request.send().await?;

        let response = check_response_success(response, "get query").await?;
        let result: QueryResponse = response.json().await?;

        if let Some(table) = result.primary_table() {
            for (row_idx, row) in table.rows.iter().enumerate() {
                let path = output_prefix.with_index(row_idx);
                let out = InsertBatch::new(context, &path);

                for (col_idx, column) in table.columns.iter().enumerate() {
                    if let Some(value) = row.get(col_idx) {
                        write_value(&out, &column.name, value).await?;
                    }
                }
            }
        }

        Ok(())
    }
}
