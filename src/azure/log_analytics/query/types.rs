use anyhow::Result;
use panopticon_core::extend::InsertBatch;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct QueryRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timespan: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QueryResponse {
    pub tables: Vec<QueryTable>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QueryTable {
    pub name: String,
    pub columns: Vec<QueryColumn>,
    pub rows: Vec<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QueryColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub column_type: String,
}

impl QueryResponse {
    pub fn primary_table(&self) -> Option<&QueryTable> {
        self.tables
            .iter()
            .find(|t| t.name == "PrimaryResult")
            .or_else(|| self.tables.first())
    }
}

impl QueryTable {
    pub fn column_index(&self, name: &str) -> Option<usize> {
        self.columns.iter().position(|c| c.name == name)
    }
}

/// Write a serde_json::Value to the output batch with the given column name
pub async fn write_value(out: &InsertBatch<'_>, name: &str, value: &serde_json::Value) -> Result<()> {
    match value {
        serde_json::Value::Null => {}
        serde_json::Value::Bool(b) => out.bool(name, *b).await?,
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.i64(name, i).await?;
            } else if let Some(f) = n.as_f64() {
                out.f64(name, f).await?;
            }
        }
        serde_json::Value::String(s) => out.string(name, s.clone()).await?,
        serde_json::Value::Array(arr) => {
            out.string(name, serde_json::to_string(arr)?).await?
        }
        serde_json::Value::Object(obj) => {
            out.string(name, serde_json::to_string(obj)?).await?
        }
    }
    Ok(())
}
