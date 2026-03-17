//! Example: Run a KQL datatable query and deserialize results into concrete structs.
//!
//! Requires env vars: TEST_CLIENT_ID, TEST_TENANT_ID, TEST_WORKSPACE_ID, TEST_ARM_PATH
//! (or a .env file in the project root).
//!
//! Run with:
//!   cargo run --example run_query

use panopticon_core::prelude::*;
use panopticon_m365::auth::{AZURE_LOG_ANALYTICS_SCOPE, AuthScope, M365_AUTH_EXT, M365Auth};
use panopticon_m365::azure::log_analytics::{LogAnalyticsWorkspace, QueryResponse};
use panopticon_m365::operations::RunQuery;
use panopticon_m365::resource::ResourceMap;
use serde::Deserialize;

/// A concrete domain type representing a sign-in event.
/// Fields match the columns produced by the datatable query below.
#[derive(Debug, Deserialize)]
struct SignInEvent {
    #[serde(rename = "Timestamp")]
    timestamp: String,
    #[serde(rename = "UserPrincipalName")]
    user_principal_name: String,
    #[serde(rename = "IPAddress")]
    ip_address: String,
    #[serde(rename = "Location")]
    location: String,
    #[serde(rename = "ResultType")]
    result_type: i64,
    #[serde(rename = "RiskLevel")]
    risk_level: String,
}

/// The shape of the RunQuery pipeline returns, used with `deserialize_returns`.
#[derive(Debug, Deserialize)]
struct QueryOutput {
    result: String,
    row_count: i64,
}

/// KQL datatable query that simulates sign-in events without requiring real log data.
const DATATABLE_QUERY: &str = r#"
datatable(
    Timestamp: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Location: string,
    ResultType: int,
    RiskLevel: string
) [
    datetime(2026-03-15T08:12:00Z), "alice@contoso.com",  "203.0.113.10", "US",  0,   "none",
    datetime(2026-03-15T08:15:00Z), "bob@contoso.com",    "198.51.100.5", "GB",  0,   "low",
    datetime(2026-03-15T08:20:00Z), "carol@contoso.com",  "192.0.2.99",   "RU",  50126, "high",
    datetime(2026-03-15T08:25:00Z), "alice@contoso.com",  "203.0.113.10", "US",  0,   "none",
    datetime(2026-03-15T08:30:00Z), "dave@contoso.com",   "198.51.100.22","DE",  0,   "medium"
]
"#;

fn load_env() -> (String, String, String, String, String, String) {
    dotenvy::dotenv().ok();
    let client_id = std::env::var("TEST_CLIENT_ID").expect("TEST_CLIENT_ID required");
    let tenant_id = std::env::var("TEST_TENANT_ID").expect("TEST_TENANT_ID required");
    let workspace_id = std::env::var("TEST_WORKSPACE_ID").expect("TEST_WORKSPACE_ID required");
    let arm_path = std::env::var("TEST_ARM_PATH").expect("TEST_ARM_PATH required");
    let subscription_id =
        std::env::var("TEST_SUBSCRIPTION_ID").expect("TEST_SUBSCRIPTION_ID required");
    let resource_group =
        std::env::var("TEST_RESOURCE_GROUP").expect("TEST_RESOURCE_GROUP required");
    (
        client_id,
        tenant_id,
        workspace_id,
        arm_path,
        subscription_id,
        resource_group,
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (client_id, tenant_id, workspace_id, arm_path, subscription_id, resource_group) =
        load_env();

    // ── 1. Authenticate (consumer responsibility, before pipeline) ──────────
    let http = oauth2::reqwest::Client::new();
    let runtime = tokio::runtime::Handle::current();
    let auth = M365Auth::new(http, runtime);

    let scope = AuthScope {
        client_id: client_id.clone(),
        tenant_id: tenant_id.clone(),
        scopes: vec![
            "offline_access".to_string(),
            AZURE_LOG_ANALYTICS_SCOPE.to_string(),
        ],
    };

    println!("Starting device code authentication...");
    let mut rx = auth.authenticate(scope);
    while let Some(event) = rx.recv().await {
        match event {
            panopticon_m365::auth::AuthEvent::DeviceCode {
                verification_uri,
                user_code,
            } => println!("\nOpen: {}\nCode: {}\n", verification_uri, user_code),
            panopticon_m365::auth::AuthEvent::Polling => print!("."),
            panopticon_m365::auth::AuthEvent::Authenticated => {
                println!("\nAuthenticated!");
                break;
            }
            panopticon_m365::auth::AuthEvent::Error(e) => {
                anyhow::bail!("Authentication failed: {}", e);
            }
        }
    }

    // ── 2. Build resource map ───────────────────────────────────────────────
    let mut workspaces = ResourceMap::new();
    workspaces.insert_labeled(
        "soc",
        LogAnalyticsWorkspace {
            label: Some("soc".into()),
            workspace_id,
            arm_path,
            subscription_id,
            resource_group,
            client_id: client_id.clone(),
            tenant_id: tenant_id.clone(),
        },
    );

    // ── 3. Build and run pipeline ───────────────────────────────────────────
    let mut pipe = Pipeline::default();

    // Extensions
    pipe.extension(M365_AUTH_EXT, auth);
    pipe.extension("workspaces", workspaces);

    // Variables
    pipe.var("workspace", "soc")?;
    pipe.var("query", DATATABLE_QUERY)?;

    // Step: run the datatable query
    pipe.step::<RunQuery>(
        "query",
        params!(
            "workspace" => Param::reference("workspace"),
            "query" => Param::reference("query"),
        ),
    )?;

    // Map step outputs to pipeline returns
    pipe.returns(
        "query",
        params!(
            "result" => Param::reference("query.result"),
            "row_count" => Param::reference("query.row_count"),
        ),
    )?;

    println!("Running pipeline...");
    let complete = pipe.compile()?.run().wait()?;

    // ── 4. Extract and deserialize results ──────────────────────────────────
    let output: QueryOutput = complete.deserialize_returns("query")?;

    println!("Debug: {:#?}", output);

    println!("\nRow count: {}", output.row_count);

    // Parse the JSON result into the typed QueryResponse
    let response: QueryResponse = serde_json::from_str(&output.result)?;
    let table = response
        .primary_table()
        .expect("Expected a primary result table");

    println!(
        "Columns: {:?}",
        table.columns.iter().map(|c| &c.name).collect::<Vec<_>>()
    );

    // Deserialize each row into a SignInEvent using column positions
    let events: Vec<SignInEvent> = table
        .rows
        .iter()
        .map(|row| {
            let obj: serde_json::Map<String, serde_json::Value> = table
                .columns
                .iter()
                .zip(row.iter())
                .map(|(col, val)| (col.name.clone(), val.clone()))
                .collect();
            serde_json::from_value(serde_json::Value::Object(obj))
                .expect("Row deserialization failed")
        })
        .collect();

    // ── 5. Use the typed results ────────────────────────────────────────────
    println!(
        "\n{:<28} {:<25} {:<16} {:<6} {:<10} {}",
        "Timestamp", "User", "IP", "Loc", "Result", "Risk"
    );
    println!("{}", "-".repeat(100));

    for event in &events {
        println!(
            "{:<28} {:<25} {:<16} {:<6} {:<10} {}",
            event.timestamp,
            event.user_principal_name,
            event.ip_address,
            event.location,
            event.result_type,
            event.risk_level,
        );
    }

    // Filter: show only risky sign-ins
    let risky: Vec<&SignInEvent> = events.iter().filter(|e| e.risk_level != "none").collect();

    println!("\n--- Risky sign-ins: {} ---", risky.len());
    for event in risky {
        println!(
            "  {} from {} ({}) - risk: {}",
            event.user_principal_name, event.ip_address, event.location, event.risk_level
        );
    }

    Ok(())
}
