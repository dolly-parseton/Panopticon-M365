use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CreatedByType {
    User,
    Application,
    ManagedIdentity,
    Key,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemData {
    pub created_at: Option<String>,
    pub created_by: Option<String>,
    pub created_by_type: Option<CreatedByType>,
    pub last_modified_at: Option<String>,
    pub last_modified_by: Option<String>,
    pub last_modified_by_type: Option<CreatedByType>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListResponse<T> {
    pub value: Vec<T>,
    #[serde(alias = "nextLink", alias = "@odata.nextLink")]
    pub next_link: Option<String>,
}
