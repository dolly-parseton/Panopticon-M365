// TODO: I think this should be moved to client module.

const ENDPOINT: &'static str = "https://login.microsoftonline.com";

// Might track compatible resources like this and add them into the builder to limit mistakes.
const DATA_RESOURCE_MONITORING: &'static str = "https://monitoring.azure.com";

/*
    Source: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api?tabs=rest#request-an-authorization-token
    ```
        curl -X POST 'https://login.microsoftonline.com/<tennant ID>/oauth2/token' \
            -H 'Content-Type: application/x-www-form-urlencoded' \
            --data-urlencode 'grant_type=client_credentials' \
            --data-urlencode 'client_id=<your apps client ID>' \
            --data-urlencode 'client_secret=<your apps client secret' \
            --data-urlencode 'resource=https://monitoring.azure.com'
    ```

    Response:
    ```
    {
        "token_type": "Bearer",
        "expires_in": "86399",
        "ext_expires_in": "86399",
        "expires_on": "1672826207",
        "not_before": "1672739507",
        "resource": "https://monitoring.azure.com",
        "access_token": "eyJ0eXAiOiJKV1Qi....gpHWoRzeDdVQd2OE3dNsLIvUIxQ"
    }
    ```
*/

#[derive(Debug)]
pub struct AuthRequestBuilder {
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub client_secret: String,
    pub resource: &'static str, // Keeps configurability minimal.
}

impl AuthRequestBuilder {
    pub fn monitoring_azure<T1, T2, T3>(tenant_id: T1, client_id: T2, client_secret: T3) -> Self
    where
        T1: Into<Uuid>,
        T2: Into<Uuid>,
        T3: Into<String>,
    {
        AuthRequestBuilder {
            tenant_id: tenant_id.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            resource: DATA_RESOURCE_MONITORING,
        }
    }

    // Not sure what HTTP client I'll be using.
    // pub fn as_request(&self) -> ??? {
    //     todo!()
    // }
}

#[derive(Debug, serde::Deserialize)]
pub struct AuthResponse {
    pub token_type: String,
    pub expires_in: u64,
    pub ext_expires_in: u64,
    pub expires_on: u64,
    pub not_before: u64,
    pub resource: String,
    pub access_token: String, // Never done secret handling, do I need to do anything special here? TODO
}
