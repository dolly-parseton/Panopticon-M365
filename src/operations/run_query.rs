use super::http::execute_endpoint;
use crate::auth::{M365Auth, M365_AUTH_EXT};
use crate::azure::log_analytics::{LogAnalyticsWorkspace, QueryEndpoint, QueryRequest};
use crate::resource::ResourceMap;
use panopticon_core::extend::*;
use panopticon_core::prelude::*;
use std::any::TypeId;

pub struct RunQuery;

const WORKSPACES_EXT: &str = "workspaces";

impl Operation for RunQuery {
    fn metadata() -> OperationMetadata
    where
        Self: Sized,
    {
        OperationMetadata {
            name: "RunQuery",
            description: "Executes a KQL query against a Log Analytics workspace",
            inputs: &[
                InputSpec {
                    name: "workspace",
                    ty: Type::Text,
                    required: true,
                    default: None,
                    description:
                        "Workspace key (label, workspace ID, or ARM path) to resolve from the ResourceMap",
                },
                InputSpec {
                    name: "query",
                    ty: Type::Text,
                    required: true,
                    default: None,
                    description: "KQL query string",
                },
                InputSpec {
                    name: "timespan",
                    ty: Type::Text,
                    required: false,
                    default: None,
                    description:
                        "ISO 8601 duration or interval (e.g. PT1H, P7D, 2024-01-01/2024-01-02)",
                },
            ],
            outputs: &[
                OutputSpec {
                    name: NameSpec::Static("result"),
                    ty: Type::Text,
                    description: "Full query response serialized as JSON",
                    scope: OutputScope::Operation,
                },
                OutputSpec {
                    name: NameSpec::Static("row_count"),
                    ty: Type::Integer,
                    description: "Number of rows in the primary result table",
                    scope: OutputScope::Operation,
                },
            ],
            requires_extensions: &[
                ExtensionSpec {
                    name: NameSpec::Static(M365_AUTH_EXT),
                    description: "M365 authentication provider",
                    type_id: || TypeId::of::<M365Auth>(),
                },
                ExtensionSpec {
                    name: NameSpec::Static(WORKSPACES_EXT),
                    description: "Log Analytics workspace resource map",
                    type_id: || TypeId::of::<ResourceMap<LogAnalyticsWorkspace>>(),
                },
            ],
        }
    }

    fn execute(context: &mut Context) -> Result<(), OperationError> {
        // Extract inputs (clone before mutating context via set_static_output).
        let auth = context.extension::<M365Auth>(M365_AUTH_EXT)?;
        let workspaces =
            context.extension::<ResourceMap<LogAnalyticsWorkspace>>(WORKSPACES_EXT)?;

        let ws_key = context.input("workspace")?.get_value()?.as_text()?.to_string();
        let query_text = context.input("query")?.get_value()?.as_text()?.to_string();
        let timespan = context
            .input("timespan")
            .ok()
            .and_then(|e| e.get_value().ok())
            .and_then(|v| v.as_text().ok())
            .map(|s| s.to_string());

        // Resolve workspace from the resource map.
        let workspace = workspaces.resolve(&ws_key).ok_or_else(|| {
            context.error(format!("Workspace '{}' not found in resource map", ws_key))
        })?;

        // Build request and execute.
        let request = QueryRequest {
            query: query_text,
            timespan,
        };

        let response =
            execute_endpoint::<QueryEndpoint>(auth, workspace, &request, "RunQuery")?;

        // Serialize full response as JSON for downstream consumption.
        let json = serde_json::to_string(&response).map_err(|e| {
            context.error(format!("Failed to serialize query response: {}", e))
        })?;

        let row_count = response
            .primary_table()
            .map(|t| t.rows.len() as i64)
            .unwrap_or(0);

        context.set_static_output(
            "result",
            StoreEntry::Var {
                value: Value::Text(json),
                ty: Type::Text,
            },
        )?;

        context.set_static_output(
            "row_count",
            StoreEntry::Var {
                value: Value::Integer(row_count),
                ty: Type::Integer,
            },
        )?;

        Ok(())
    }
}
