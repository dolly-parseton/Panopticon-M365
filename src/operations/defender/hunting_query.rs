use crate::auth::{M365_AUTH_EXT, M365Auth};
use crate::defender::advanced_hunting::{DefenderXdr, HuntingRequest, RunHuntingQueryEndpoint};
use crate::operations::http::execute_endpoint;
use crate::resource::ResourceMap;
use panopticon_core::extend::*;
use panopticon_core::prelude::*;
use std::any::TypeId;

pub struct RunHuntingQuery;

const DEFENDER_XDR_EXT: &str = "defender_xdr";

impl Operation for RunHuntingQuery {
    fn metadata() -> OperationMetadata
    where
        Self: Sized,
    {
        OperationMetadata {
            name: "RunHuntingQuery",
            description: "Executes a KQL query via Defender XDR Advanced Hunting",
            inputs: &[
                InputSpec {
                    name: "tenant",
                    ty: Type::Text,
                    required: true,
                    default: None,
                    description: "Tenant key (label or tenant ID) to resolve from the ResourceMap",
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
                    description: "ISO 8601 duration or interval (e.g. PT1H, P7D, 2024-01-01/2024-01-02)",
                },
            ],
            outputs: &[
                OutputSpec {
                    name: NameSpec::Static("result"),
                    ty: Type::Text,
                    description: "Full hunting response serialized as JSON",
                    scope: OutputScope::Operation,
                },
                OutputSpec {
                    name: NameSpec::Static("row_count"),
                    ty: Type::Integer,
                    description: "Number of result rows returned",
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
                    name: NameSpec::Static(DEFENDER_XDR_EXT),
                    description: "Defender XDR tenant resource map",
                    type_id: || TypeId::of::<ResourceMap<DefenderXdr>>(),
                },
            ],
        }
    }

    fn execute(context: &mut Context) -> Result<(), OperationError> {
        let auth = context.extension::<M365Auth>(M365_AUTH_EXT)?;
        let tenants = context.extension::<ResourceMap<DefenderXdr>>(DEFENDER_XDR_EXT)?;

        let tenant_key = context.input("tenant")?.get_value()?.as_text()?.to_string();
        let query_text = context.input("query")?.get_value()?.as_text()?.to_string();
        let timespan = context
            .input("timespan")
            .ok()
            .and_then(|e| e.get_value().ok())
            .and_then(|v| v.as_text().ok())
            .map(|s| s.to_string());

        let defender = tenants.resolve(&tenant_key).ok_or_else(|| {
            context.error(format!(
                "Defender XDR tenant '{}' not found in resource map",
                tenant_key
            ))
        })?;

        let request = HuntingRequest {
            query: query_text,
            timespan,
        };

        let response = execute_endpoint::<RunHuntingQueryEndpoint>(
            auth,
            defender,
            &request,
            "RunHuntingQuery",
        )?;

        let json = serde_json::to_string(&response)
            .map_err(|e| context.error(format!("Failed to serialize hunting response: {}", e)))?;

        let row_count = response.row_count() as i64;

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
