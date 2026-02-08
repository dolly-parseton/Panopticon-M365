use super::types::*;
use crate::azure::common::{
    check_response_success, client_id_attribute, get_log_analytics_token, query_attribute,
    resource_path_attribute, tenant_id_attribute, timespan_attribute,
};
use crate::azure::log_analytics::ResourceTarget;
use crate::impl_descriptor;
use anyhow::Result;
use panopticon_core::extend::*;
use panopticon_core::prelude::*;

static EXECUTE_RESOURCE_QUERY_SPEC: CommandSchema = LazyLock::new(|| {
    CommandSpecBuilder::new()
        .attribute(client_id_attribute())
        .attribute(tenant_id_attribute())
        .attribute(resource_path_attribute())
        .attribute(query_attribute())
        .attribute(timespan_attribute())
        .build()
});

pub struct ExecuteResourceQueryCommand {
    pub client_id: String,
    pub tenant_id: String,
    pub target: ResourceTarget,
    pub query: String,
    pub timespan: Option<String>,
}

impl_descriptor!(
    ExecuteResourceQueryCommand,
    "ExecuteResourceQueryCommand",
    EXECUTE_RESOURCE_QUERY_SPEC
);

impl FromAttributes for ExecuteResourceQueryCommand {
    fn from_attributes(attrs: &Attributes) -> Result<Self> {
        let client_id = attrs.get_required_string("client_id")?;
        let tenant_id = attrs.get_required_string("tenant_id")?;

        let resource_path = attrs.get_required_string("resource_path")?;
        let target = ResourceTarget::try_from(resource_path.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid resource_path: {}", e))?;

        let query = attrs.get_required_string("query")?;
        let timespan = attrs.get_optional_string("timespan");

        Ok(ExecuteResourceQueryCommand {
            client_id,
            tenant_id,
            target,
            query,
            timespan,
        })
    }
}

#[async_trait]
impl Executable for ExecuteResourceQueryCommand {
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

        let response = check_response_success(response, "execute resource query").await?;
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
        let resource_path =
            std::env::var("TEST_RESOURCE_PATH").expect("TEST_RESOURCE_PATH env var required");

        (client_id, tenant_id, resource_path)
    }

    #[tokio::test]
    #[ignore] // Requires interactive device code flow
    async fn test_execute_resource_query_with_datatable() -> anyhow::Result<()> {
        let (client_id, tenant_id, resource_path) = load_test_env();

        let services = PipelineServices::defaults();
        let mut pipeline = Pipeline::with_services(services);

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

        let query_attrs = ObjectBuilder::new()
            .insert("client_id", client_id.as_str())
            .insert("tenant_id", tenant_id.as_str())
            .insert("resource_path", resource_path.as_str())
            .insert(
                "query",
                r#"datatable(Status:string, Code:int) ["OK", 200, "NotFound", 404]"#,
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
            .add_command::<ExecuteResourceQueryCommand>("run", &query_attrs)
            .await?;

        let completed = pipeline.compile().await?.execute().await?;
        let results = completed.results(ResultSettings::default()).await?;

        let source = StorePath::from_segments(["query", "run"]);
        let cmd_results = results.get_by_source(&source).expect("Expected query.run results");

        let row0 = cmd_results
            .data_get(&source.with_index(0).with_segment("Status"))
            .expect("Expected Status in row 0");
        assert_eq!(row0.to_string(), "OK");

        let row1 = cmd_results
            .data_get(&source.with_index(1).with_segment("Code"))
            .expect("Expected Code in row 1");
        assert_eq!(row1.to_string(), "404");

        Ok(())
    }
}
