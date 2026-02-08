use serde::{Deserialize, Serialize};

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
