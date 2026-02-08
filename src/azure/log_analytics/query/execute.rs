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

static EXECUTE_QUERY_SPEC: CommandSchema = LazyLock::new(|| {
    CommandSpecBuilder::new()
        .attribute(client_id_attribute())
        .attribute(tenant_id_attribute())
        .attribute(workspace_id_attribute())
        .attribute(query_attribute())
        .attribute(timespan_attribute())
        .build()
});

pub struct ExecuteQueryCommand {
    pub client_id: String,
    pub tenant_id: String,
    pub target: Target,
    pub query: String,
    pub timespan: Option<String>,
}

impl_descriptor!(ExecuteQueryCommand, "ExecuteQueryCommand", EXECUTE_QUERY_SPEC);

impl FromAttributes for ExecuteQueryCommand {
    fn from_attributes(attrs: &Attributes) -> Result<Self> {
        let client_id = attrs.get_required_string("client_id")?;
        let tenant_id = attrs.get_required_string("tenant_id")?;

        let workspace_id = attrs.get_required_string("workspace_id")?;
        let target = Target::try_from(workspace_id.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid workspace_id: {}", e))?;

        let query = attrs.get_required_string("query")?;
        let timespan = attrs.get_optional_string("timespan");

        Ok(ExecuteQueryCommand {
            client_id,
            tenant_id,
            target,
            query,
            timespan,
        })
    }
}

#[async_trait]
impl Executable for ExecuteQueryCommand {
    async fn execute(&self, context: &ExecutionContext, output_prefix: &StorePath) -> Result<()> {
        let (http, token) =
            get_log_analytics_token(context, &self.client_id, &self.tenant_id).await?;

        let url = self.target.query_url();
        let body = QueryRequest {
            query: self.query.clone(),
            timespan: self.timespan.clone(),
        };

        let response = http
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let response = check_response_success(response, "execute query").await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::m365_auth::M365AuthCommand;

    fn load_test_env() -> (String, String, String) {
        dotenvy::dotenv().ok();

        let client_id =
            std::env::var("TEST_CLIENT_ID").expect("TEST_CLIENT_ID env var required");
        let tenant_id =
            std::env::var("TEST_TENANT_ID").expect("TEST_TENANT_ID env var required");
        let workspace_id =
            std::env::var("TEST_WORKSPACE_ID").expect("TEST_WORKSPACE_ID env var required");

        (client_id, tenant_id, workspace_id)
    }

    #[tokio::test]
    #[ignore] // Requires interactive device code flow
    async fn test_execute_query_with_datatable() -> anyhow::Result<()> {
        let (client_id, tenant_id, workspace_id) = load_test_env();

        let services = PipelineServices::defaults();
        let mut pipeline = Pipeline::with_services(services);

        // Auth command attributes
        let auth_attrs = ObjectBuilder::new()
            .insert(
                "sessions",
                ScalarValue::Array(vec![ObjectBuilder::new()
                    .insert("client_id", client_id.as_str())
                    .insert("tenant_id", tenant_id.as_str())
                    .insert(
                        "scopes",
                        ScalarValue::Array(vec![ScalarValue::String(
                            "https://api.loganalytics.azure.com/.default".to_string(),
                        )]),
                    )
                    .build_scalar()]),
            )
            .build_hashmap();

        // Query command attributes using datatable
        let query_attrs = ObjectBuilder::new()
            .insert("client_id", client_id.as_str())
            .insert("tenant_id", tenant_id.as_str())
            .insert("workspace_id", workspace_id.as_str())
            .insert(
                "query",
                r#"datatable(Name:string, Value:int) ["Alice", 30, "Bob", 25]"#,
            )
            .build_hashmap();

        pipeline
            .add_namespace(NamespaceBuilder::new("auth"))
            .await?
            .add_command::<M365AuthCommand>("init", &auth_attrs)
            .await?;

        pipeline
            .add_namespace(NamespaceBuilder::new("query"))
            .await?
            .add_command::<ExecuteQueryCommand>("run", &query_attrs)
            .await?;

        let completed = pipeline.compile().await?.execute().await?;
        let results = completed.results(ResultSettings::default()).await?;

        let source = StorePath::from_segments(["query", "run"]);
        let cmd_results = results.get_by_source(&source).expect("Expected query.run results");

        // Should have 2 rows from datatable
        let row0 = cmd_results
            .data_get(&source.with_index(0).with_segment("Name"))
            .expect("Expected Name in row 0");
        assert_eq!(row0.to_string(), "Alice");

        let row1 = cmd_results
            .data_get(&source.with_index(1).with_segment("Name"))
            .expect("Expected Name in row 1");
        assert_eq!(row1.to_string(), "Bob");

        Ok(())
    }
}
