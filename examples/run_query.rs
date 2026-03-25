//! Example: Run KQL queries against both Sentinel (Log Analytics) and Defender XDR (Advanced Hunting).
//!
//! Requires env vars: TEST_CLIENT_ID, TEST_TENANT_ID, TEST_WORKSPACE_ID, TEST_ARM_PATH,
//! TEST_SUBSCRIPTION_ID, TEST_RESOURCE_GROUP (or a .env file in the project root).
//!
//! Run with:
//!   cargo run --example run_query

use panopticon_core::prelude::*;
use panopticon_m365::auth::{AZURE_LOG_ANALYTICS_SCOPE, AuthScope, M365_AUTH_EXT, M365Auth};
use panopticon_m365::azure::log_analytics::{LogAnalyticsWorkspace, QueryResponse};
use panopticon_m365::defender::advanced_hunting::{DefenderXdr, HuntingResponse};
use panopticon_m365::operations::{RunHuntingQuery, RunSentinelQuery};
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

/// The shape of pipeline returns for both operations.
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

/// Defender XDR Advanced Hunting datatable query — simulates device network events.
const HUNTING_QUERY: &str = r#"
datatable(
    Timestamp: datetime,
    DeviceName: string,
    RemoteIP: string,
    RemotePort: int,
    ActionType: string,
    ConnectionCount: long
) [
    datetime(2026-03-17T10:01:00Z), "DESKTOP-SOC01",  "198.51.100.10", 443,  "ConnectionSuccess", 42,
    datetime(2026-03-17T10:02:00Z), "DESKTOP-SOC01",  "203.0.113.55",  8080, "ConnectionSuccess", 15,
    datetime(2026-03-17T10:03:00Z), "SERVER-DC01",     "192.0.2.1",     53,   "ConnectionSuccess", 128,
    datetime(2026-03-17T10:04:00Z), "LAPTOP-IR02",     "198.51.100.77", 22,   "ConnectionSuccess", 3,
    datetime(2026-03-17T10:05:00Z), "SERVER-WEB03",    "203.0.113.200", 443,  "ConnectionBlocked", 87
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

/// Run the device code flow for a given scope, printing prompts to stdout.
async fn authenticate(auth: &M365Auth, scope: AuthScope) -> anyhow::Result<()> {
    println!(
        "Authenticating for scope: {} ...",
        scope.scopes.last().unwrap_or(&"?".to_string())
    );
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
                return Ok(());
            }
            panopticon_m365::auth::AuthEvent::Error(e) => {
                anyhow::bail!("Authentication failed: {}", e);
            }
        }
    }
    anyhow::bail!("Authentication channel closed unexpectedly")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (client_id, tenant_id, workspace_id, arm_path, subscription_id, resource_group) =
        load_env();

    // ── 1. Authenticate ────────────────────────────────────────────────────────
    // One interactive device code flow per (client_id, tenant_id) pair.
    // The refresh token is then used to silently acquire tokens for any
    // additional resource scopes (e.g. Graph API) — no extra user interaction.
    let http = oauth2::reqwest::Client::new();
    let runtime = tokio::runtime::Handle::current();
    let auth = M365Auth::new(http, runtime);

    authenticate(
        &auth,
        AuthScope {
            client_id: client_id.clone(),
            tenant_id: tenant_id.clone(),
            scopes: vec![
                "offline_access".to_string(),
                AZURE_LOG_ANALYTICS_SCOPE.to_string(),
            ],
        },
    )
    .await?;

    // ── 2. Build resource maps ───────────────────────────────────────────────
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

    let mut defenders = ResourceMap::new();
    defenders.insert_labeled(
        "xdr",
        DefenderXdr {
            label: Some("xdr".into()),
            client_id: client_id.clone(),
            tenant_id: tenant_id.clone(),
        },
    );

    // ── 3. Build and run pipeline ────────────────────────────────────────────
    let mut pipe = Pipeline::default();

    // Extensions
    pipe.extension(M365_AUTH_EXT, auth);
    pipe.extension("workspaces", workspaces);
    pipe.extension("defender_xdr", defenders);

    // Variables
    pipe.var("workspace", "soc")?;
    pipe.var("sentinel_query", DATATABLE_QUERY)?;
    pipe.var("tenant", "xdr")?;
    pipe.var("hunting_query", HUNTING_QUERY)?;

    // Step 1: Sentinel query against Log Analytics
    pipe.step::<RunSentinelQuery>(
        "sentinel",
        params!(
            "workspace" => Param::reference("workspace"),
            "query" => Param::reference("sentinel_query"),
        ),
    )?;

    // Step 2: Defender XDR Advanced Hunting query
    pipe.step::<RunHuntingQuery>(
        "hunting",
        params!(
            "tenant" => Param::reference("tenant"),
            "query" => Param::reference("hunting_query"),
        ),
    )?;

    // Map step outputs to pipeline returns
    pipe.returns(
        "sentinel",
        params!(
            "result" => Param::reference("sentinel.result"),
            "row_count" => Param::reference("sentinel.row_count"),
        ),
    )?;
    pipe.returns(
        "hunting",
        params!(
            "result" => Param::reference("hunting.result"),
            "row_count" => Param::reference("hunting.row_count"),
        ),
    )?;

    println!("Running pipeline...");
    let complete = pipe.compile()?.run().wait()?;

    // ── 4. Sentinel results ──────────────────────────────────────────────────
    println!("\n=== Sentinel (Log Analytics) ===");
    let sentinel_output: QueryOutput = complete.deserialize_returns("sentinel")?;
    println!("Row count: {}", sentinel_output.row_count);

    let response: QueryResponse = serde_json::from_str(&sentinel_output.result)?;
    let table = response
        .primary_table()
        .expect("Expected a primary result table");

    println!(
        "Columns: {:?}",
        table.columns.iter().map(|c| &c.name).collect::<Vec<_>>()
    );

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

    let risky: Vec<&SignInEvent> = events.iter().filter(|e| e.risk_level != "none").collect();
    println!("\n--- Risky sign-ins: {} ---", risky.len());
    for event in risky {
        println!(
            "  {} from {} ({}) - risk: {}",
            event.user_principal_name, event.ip_address, event.location, event.risk_level
        );
    }

    // ── 5. Defender XDR results ──────────────────────────────────────────────
    println!("\n=== Defender XDR (Advanced Hunting) ===");
    let hunting_output: QueryOutput = complete.deserialize_returns("hunting")?;
    println!("Row count: {}", hunting_output.row_count);

    let hunting_response: HuntingResponse = serde_json::from_str(&hunting_output.result)?;
    println!(
        "Schema: {:?}",
        hunting_response
            .schema
            .iter()
            .map(|c| &c.name)
            .collect::<Vec<_>>()
    );

    for row in &hunting_response.results {
        let device = row
            .get("DeviceName")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let ip = row.get("RemoteIP").and_then(|v| v.as_str()).unwrap_or("?");
        let count = row
            .get("ConnectionCount")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        println!("  {:<30} {:<20} {} connections", device, ip, count);
    }

    Ok(())
}
