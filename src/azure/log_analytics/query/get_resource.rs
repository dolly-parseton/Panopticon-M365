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

static GET_RESOURCE_QUERY_SPEC: CommandSchema = LazyLock::new(|| {
    CommandSpecBuilder::new()
        .attribute(client_id_attribute())
        .attribute(tenant_id_attribute())
        .attribute(resource_path_attribute())
        .attribute(query_attribute())
        .attribute(timespan_attribute())
        .build()
});

pub struct GetResourceQueryCommand {
    pub client_id: String,
    pub tenant_id: String,
    pub target: ResourceTarget,
    pub query: String,
    pub timespan: Option<String>,
}

impl_descriptor!(
    GetResourceQueryCommand,
    "GetResourceQueryCommand",
    GET_RESOURCE_QUERY_SPEC
);

impl FromAttributes for GetResourceQueryCommand {
    fn from_attributes(attrs: &Attributes) -> Result<Self> {
        let client_id = attrs.get_required_string("client_id")?;
        let tenant_id = attrs.get_required_string("tenant_id")?;

        let resource_path = attrs.get_required_string("resource_path")?;
        let target = ResourceTarget::try_from(resource_path.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid resource_path: {}", e))?;

        let query = attrs.get_required_string("query")?;
        let timespan = attrs.get_optional_string("timespan");

        Ok(GetResourceQueryCommand {
            client_id,
            tenant_id,
            target,
            query,
            timespan,
        })
    }
}

#[async_trait]
impl Executable for GetResourceQueryCommand {
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

        let response = check_response_success(response, "get resource query").await?;
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
    async fn test_get_resource_query_with_datatable() -> anyhow::Result<()> {
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
                r#"datatable(Event:string, Severity:int) ["Login", 1, "Logout", 1, "Error", 3]"#,
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
            .add_command::<GetResourceQueryCommand>("run", &query_attrs)
            .await?;

        let completed = pipeline.compile().await?.execute().await?;
        let results = completed.results(ResultSettings::default()).await?;

        let source = StorePath::from_segments(["query", "run"]);
        let cmd_results = results.get_by_source(&source).expect("Expected query.run results");

        // Should have 3 rows
        let row0 = cmd_results
            .data_get(&source.with_index(0).with_segment("Event"))
            .expect("Expected Event in row 0");
        assert_eq!(row0.to_string(), "Login");

        let row2 = cmd_results
            .data_get(&source.with_index(2).with_segment("Severity"))
            .expect("Expected Severity in row 2");
        assert_eq!(row2.to_string(), "3");

        Ok(())
    }
}
