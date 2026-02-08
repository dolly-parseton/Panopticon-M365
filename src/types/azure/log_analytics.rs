use serde::{Deserialize, Serialize};

// ── Query types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct QueryBody {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timespan: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspaces: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QueryResponse {
    pub tables: Vec<Table>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Table {
    pub name: String,
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Column {
    pub name: String,
    #[serde(rename = "type")]
    pub column_type: String,
}

// ── Metadata types ──────────────────────────────────────────────────────────
//
// The full metadata response contains many sections (functions, queries,
// solutions, categories, resourceTypes, permissions, etc). Only the most
// immediately useful fields are typed here; expand as needed.

#[derive(Debug, Clone, Deserialize)]
pub struct MetadataResponse {
    #[serde(default)]
    pub tables: Vec<MetadataTable>,
    #[serde(default)]
    pub functions: Vec<MetadataFunction>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataTable {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub time_span: Option<String>,
    #[serde(default)]
    pub columns: Vec<MetadataColumn>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub column_type: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataFunction {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
}
