// Microsoft Sentinel Incidents REST API Types (API Version 2025-09-01)
// Source: https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// ENUMS
// ============================================================================

// The severity of the incident
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentSeverity {
    High,
    Medium,
    Low,
    Informational,
}

// The status of the incident
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentStatus {
    New,
    Active,
    Closed,
}

// The reason the incident was closed
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentClassification {
    Undetermined,
    TruePositive,
    BenignPositive,
    FalsePositive,
}

// The classification reason the incident was closed with
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentClassificationReason {
    SuspiciousActivity,
    SuspiciousButExpected,
    IncorrectAlertLogic,
    InaccurateData,
}

// The type of the incident label
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentLabelType {
    User,
    AutoAssigned,
}

// The type of the owner
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerType {
    Unknown,
    User,
    Group,
}

// The type of identity that created/modified the resource
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreatedByType {
    User,
    Application,
    ManagedIdentity,
    Key,
}

// MITRE ATT&CK tactics
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackTactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    Exfiltration,
    CommandAndControl,
    Impact,
    PreAttack,
    ImpairProcessControl,
    InhibitResponseFunction,
}

// The severity of the alert
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    High,
    Medium,
    Low,
    Informational,
}

// The status of the alert
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertStatus {
    Unknown,
    New,
    Resolved,
    Dismissed,
    InProgress,
}

// The confidence level of the alert
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    Unknown,
    Low,
    High,
}

// The confidence score calculation status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceScoreStatus {
    NotApplicable,
    InProcess,
    NotFinal,
    Final,
}

// Kill chain intent
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KillChainIntent {
    Unknown,
    Probing,
    Exploitation,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Execution,
    Collection,
    Exfiltration,
    CommandAndControl,
    Impact,
}

// The kind of entity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityKind {
    Account,
    Host,
    File,
    AzureResource,
    CloudApplication,
    DnsResolution,
    FileHash,
    Ip,
    Malware,
    Process,
    RegistryKey,
    RegistryValue,
    SecurityGroup,
    Url,
    IoTDevice,
    SecurityAlert,
    Bookmark,
    Mailbox,
    MailCluster,
    MailMessage,
    SubmissionMail,
}

// The elevation token of a process
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElevationToken {
    Default,
    Full,
    Limited,
}

// The hash algorithm type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileHashAlgorithm {
    Unknown,
    MD5,
    SHA1,
    SHA256,
    SHA256AC,
}

// The operating system family
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OSFamily {
    Linux,
    Windows,
    Android,
    IOS,
    Unknown,
}

// Windows registry hive
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryHive {
    #[serde(rename = "HKEY_LOCAL_MACHINE")]
    HkeyLocalMachine,
    #[serde(rename = "HKEY_CLASSES_ROOT")]
    HkeyClassesRoot,
    #[serde(rename = "HKEY_CURRENT_CONFIG")]
    HkeyCurrentConfig,
    #[serde(rename = "HKEY_USERS")]
    HkeyUsers,
    #[serde(rename = "HKEY_CURRENT_USER_LOCAL_SETTINGS")]
    HkeyCurrentUserLocalSettings,
    #[serde(rename = "HKEY_PERFORMANCE_DATA")]
    HkeyPerformanceData,
    #[serde(rename = "HKEY_PERFORMANCE_NLSTEXT")]
    HkeyPerformanceNlstext,
    #[serde(rename = "HKEY_PERFORMANCE_TEXT")]
    HkeyPerformanceText,
    #[serde(rename = "HKEY_A")]
    HkeyA,
    #[serde(rename = "HKEY_CURRENT_USER")]
    HkeyCurrentUser,
}

// Windows registry value kind
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryValueKind {
    None,
    Unknown,
    String,
    ExpandString,
    Binary,
    DWord,
    MultiString,
    QWord,
}

// Antispam mail direction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AntispamMailDirection {
    Unknown,
    Inbound,
    Outbound,
    Intraorg,
}

// Mail delivery action
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryAction {
    Unknown,
    DeliveredAsSpam,
    Delivered,
    Blocked,
    Replaced,
}

// Mail delivery location
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryLocation {
    Unknown,
    Inbox,
    JunkFolder,
    DeletedFolder,
    Quarantine,
    External,
    Failed,
    Dropped,
    Forwarded,
}

// ============================================================================
// CORE INCIDENT STRUCTS
// ============================================================================

// Represents an incident in Azure Security Insights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<IncidentProperties>,
}

// Incident properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentProperties {
    pub title: String,
    pub severity: IncidentSeverity,
    pub status: IncidentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "createdTimeUtc", skip_serializing_if = "Option::is_none")]
    pub created_time_utc: Option<String>,
    #[serde(
        rename = "lastModifiedTimeUtc",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_modified_time_utc: Option<String>,
    #[serde(
        rename = "firstActivityTimeUtc",
        skip_serializing_if = "Option::is_none"
    )]
    pub first_activity_time_utc: Option<String>,
    #[serde(
        rename = "lastActivityTimeUtc",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_activity_time_utc: Option<String>,
    #[serde(rename = "incidentNumber", skip_serializing_if = "Option::is_none")]
    pub incident_number: Option<i32>,
    #[serde(rename = "incidentUrl", skip_serializing_if = "Option::is_none")]
    pub incident_url: Option<String>,
    #[serde(rename = "providerName", skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    #[serde(rename = "providerIncidentId", skip_serializing_if = "Option::is_none")]
    pub provider_incident_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<IncidentClassification>,
    #[serde(
        rename = "classificationComment",
        skip_serializing_if = "Option::is_none"
    )]
    pub classification_comment: Option<String>,
    #[serde(
        rename = "classificationReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub classification_reason: Option<IncidentClassificationReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<IncidentOwnerInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<IncidentLabel>>,
    #[serde(
        rename = "relatedAnalyticRuleIds",
        skip_serializing_if = "Option::is_none"
    )]
    pub related_analytic_rule_ids: Option<Vec<String>>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<IncidentAdditionalData>,
}

// Information on the user an incident is assigned to
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentOwnerInfo {
    #[serde(rename = "objectId", skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(rename = "userPrincipalName", skip_serializing_if = "Option::is_none")]
    pub user_principal_name: Option<String>,
    #[serde(rename = "assignedTo", skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<String>,
    #[serde(rename = "ownerType", skip_serializing_if = "Option::is_none")]
    pub owner_type: Option<OwnerType>,
}

// Represents an incident label
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentLabel {
    #[serde(rename = "labelName", skip_serializing_if = "Option::is_none")]
    pub label_name: Option<String>,
    #[serde(rename = "labelType", skip_serializing_if = "Option::is_none")]
    pub label_type: Option<IncidentLabelType>,
}

// Incident additional data property bag
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentAdditionalData {
    #[serde(rename = "alertsCount", skip_serializing_if = "Option::is_none")]
    pub alerts_count: Option<i32>,
    #[serde(rename = "bookmarksCount", skip_serializing_if = "Option::is_none")]
    pub bookmarks_count: Option<i32>,
    #[serde(rename = "commentsCount", skip_serializing_if = "Option::is_none")]
    pub comments_count: Option<i32>,
    #[serde(rename = "alertProductNames", skip_serializing_if = "Option::is_none")]
    pub alert_product_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactics: Option<Vec<AttackTactic>>,
    #[serde(
        rename = "providerIncidentUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub provider_incident_url: Option<String>,
}

// List of incidents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentList {
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Vec<Incident>>,
}

// ============================================================================
// ALERT STRUCTS
// ============================================================================

// List of incident alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentAlertList {
    pub value: Vec<SecurityAlert>,
}

// Security alert entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SecurityAlertProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

// Security alert properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlertProperties {
    #[serde(rename = "systemAlertId", skip_serializing_if = "Option::is_none")]
    pub system_alert_id: Option<String>,
    #[serde(rename = "alertDisplayName", skip_serializing_if = "Option::is_none")]
    pub alert_display_name: Option<String>,
    #[serde(rename = "alertLink", skip_serializing_if = "Option::is_none")]
    pub alert_link: Option<String>,
    #[serde(rename = "alertType", skip_serializing_if = "Option::is_none")]
    pub alert_type: Option<String>,
    #[serde(rename = "compromisedEntity", skip_serializing_if = "Option::is_none")]
    pub compromised_entity: Option<String>,
    #[serde(rename = "confidenceLevel", skip_serializing_if = "Option::is_none")]
    pub confidence_level: Option<ConfidenceLevel>,
    #[serde(rename = "confidenceReasons", skip_serializing_if = "Option::is_none")]
    pub confidence_reasons: Option<Vec<ConfidenceReasons>>,
    #[serde(rename = "confidenceScore", skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<f64>,
    #[serde(
        rename = "confidenceScoreStatus",
        skip_serializing_if = "Option::is_none"
    )]
    pub confidence_score_status: Option<ConfidenceScoreStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "endTimeUtc", skip_serializing_if = "Option::is_none")]
    pub end_time_utc: Option<String>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<KillChainIntent>,
    #[serde(rename = "processingEndTime", skip_serializing_if = "Option::is_none")]
    pub processing_end_time: Option<String>,
    #[serde(
        rename = "productComponentName",
        skip_serializing_if = "Option::is_none"
    )]
    pub product_component_name: Option<String>,
    #[serde(rename = "productName", skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    #[serde(rename = "productVersion", skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,
    #[serde(rename = "providerAlertId", skip_serializing_if = "Option::is_none")]
    pub provider_alert_id: Option<String>,
    #[serde(rename = "remediationSteps", skip_serializing_if = "Option::is_none")]
    pub remediation_steps: Option<Vec<String>>,
    #[serde(
        rename = "resourceIdentifiers",
        skip_serializing_if = "Option::is_none"
    )]
    pub resource_identifiers: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<AlertSeverity>,
    #[serde(rename = "startTimeUtc", skip_serializing_if = "Option::is_none")]
    pub start_time_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AlertStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactics: Option<Vec<AttackTactic>>,
    #[serde(rename = "timeGenerated", skip_serializing_if = "Option::is_none")]
    pub time_generated: Option<String>,
    #[serde(rename = "vendorName", skip_serializing_if = "Option::is_none")]
    pub vendor_name: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// Confidence reasons for an alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceReasons {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "reasonType", skip_serializing_if = "Option::is_none")]
    pub reason_type: Option<String>,
}

// ============================================================================
// BOOKMARK STRUCTS
// ============================================================================

// List of incident bookmarks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentBookmarkList {
    pub value: Vec<HuntingBookmark>,
}

// Hunting bookmark entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntingBookmark {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HuntingBookmarkProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

// Hunting bookmark properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntingBookmarkProperties {
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(rename = "createdBy", skip_serializing_if = "Option::is_none")]
    pub created_by: Option<UserInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(rename = "updatedBy", skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<UserInfo>,
    #[serde(rename = "eventTime", skip_serializing_if = "Option::is_none")]
    pub event_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(rename = "queryResult", skip_serializing_if = "Option::is_none")]
    pub query_result: Option<String>,
    #[serde(rename = "incidentInfo", skip_serializing_if = "Option::is_none")]
    pub incident_info: Option<IncidentInfo>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// User information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "objectId", skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
}

// Incident information for a bookmark
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentInfo {
    #[serde(rename = "incidentId", skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<String>,
    #[serde(rename = "relationName", skip_serializing_if = "Option::is_none")]
    pub relation_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<IncidentSeverity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

// ============================================================================
// ENTITY STRUCTS
// ============================================================================

// Response for list entities operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentEntitiesResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities: Option<Vec<Entity>>,
    #[serde(rename = "metaData", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Vec<IncidentEntitiesResultsMetadata>>,
}

// Metadata for entity results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentEntitiesResultsMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i32>,
    #[serde(rename = "entityKind", skip_serializing_if = "Option::is_none")]
    pub entity_kind: Option<EntityKind>,
}

// Base entity structure (polymorphic based on kind)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Entity {
    Account(AccountEntity),
    Host(HostEntity),
    File(FileEntity),
    FileHash(FileHashEntity),
    AzureResource(AzureResourceEntity),
    CloudApplication(CloudApplicationEntity),
    DnsResolution(DnsEntity),
    Ip(IpEntity),
    Malware(MalwareEntity),
    Process(ProcessEntity),
    RegistryKey(RegistryKeyEntity),
    RegistryValue(RegistryValueEntity),
    SecurityGroup(SecurityGroupEntity),
    Url(UrlEntity),
    IoTDevice(IoTDeviceEntity),
    SecurityAlert(SecurityAlertEntity),
    Bookmark(BookmarkEntity),
    Mailbox(MailboxEntity),
    MailCluster(MailClusterEntity),
    MailMessage(MailMessageEntity),
    SubmissionMail(SubmissionMailEntity),
}

// Account entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<AccountEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountEntityProperties {
    #[serde(rename = "aadTenantId", skip_serializing_if = "Option::is_none")]
    pub aad_tenant_id: Option<String>,
    #[serde(rename = "aadUserId", skip_serializing_if = "Option::is_none")]
    pub aad_user_id: Option<String>,
    #[serde(rename = "accountName", skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "dnsDomain", skip_serializing_if = "Option::is_none")]
    pub dns_domain: Option<String>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "hostEntityId", skip_serializing_if = "Option::is_none")]
    pub host_entity_id: Option<String>,
    #[serde(rename = "isDomainJoined", skip_serializing_if = "Option::is_none")]
    pub is_domain_joined: Option<bool>,
    #[serde(rename = "ntDomain", skip_serializing_if = "Option::is_none")]
    pub nt_domain: Option<String>,
    #[serde(rename = "objectGuid", skip_serializing_if = "Option::is_none")]
    pub object_guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub puid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(rename = "upnSuffix", skip_serializing_if = "Option::is_none")]
    pub upn_suffix: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// Host entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HostEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntityProperties {
    #[serde(rename = "azureID", skip_serializing_if = "Option::is_none")]
    pub azure_id: Option<String>,
    #[serde(rename = "dnsDomain", skip_serializing_if = "Option::is_none")]
    pub dns_domain: Option<String>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "hostName", skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    #[serde(rename = "isDomainJoined", skip_serializing_if = "Option::is_none")]
    pub is_domain_joined: Option<bool>,
    #[serde(rename = "netBiosName", skip_serializing_if = "Option::is_none")]
    pub net_bios_name: Option<String>,
    #[serde(rename = "ntDomain", skip_serializing_if = "Option::is_none")]
    pub nt_domain: Option<String>,
    #[serde(rename = "omsAgentID", skip_serializing_if = "Option::is_none")]
    pub oms_agent_id: Option<String>,
    #[serde(rename = "osFamily", skip_serializing_if = "Option::is_none")]
    pub os_family: Option<OSFamily>,
    #[serde(rename = "osVersion", skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// File entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<FileEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntityProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
    #[serde(rename = "fileHashEntityIds", skip_serializing_if = "Option::is_none")]
    pub file_hash_entity_ids: Option<Vec<String>>,
    #[serde(rename = "fileName", skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "hostEntityId", skip_serializing_if = "Option::is_none")]
    pub host_entity_id: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// File hash entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<FileHashEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashEntityProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<FileHashAlgorithm>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "hashValue", skip_serializing_if = "Option::is_none")]
    pub hash_value: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// Azure resource entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureResourceEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<AzureResourceEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureResourceEntityProperties {
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "resourceId", skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(rename = "subscriptionId", skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// Cloud application entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudApplicationEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<CloudApplicationEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudApplicationEntityProperties {
    #[serde(rename = "appId", skip_serializing_if = "Option::is_none")]
    pub app_id: Option<i32>,
    #[serde(rename = "appName", skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "instanceName", skip_serializing_if = "Option::is_none")]
    pub instance_name: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// DNS entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<DnsEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEntityProperties {
    #[serde(
        rename = "dnsServerIpEntityId",
        skip_serializing_if = "Option::is_none"
    )]
    pub dns_server_ip_entity_id: Option<String>,
    #[serde(rename = "domainName", skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(
        rename = "hostIpAddressEntityId",
        skip_serializing_if = "Option::is_none"
    )]
    pub host_ip_address_entity_id: Option<String>,
    #[serde(rename = "ipAddressEntityIds", skip_serializing_if = "Option::is_none")]
    pub ip_address_entity_ids: Option<Vec<String>>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// IP entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<IpEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpEntityProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<GeoLocation>,
    #[serde(rename = "threatIntelligence", skip_serializing_if = "Option::is_none")]
    pub threat_intelligence: Option<Vec<ThreatIntelligence>>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// Geographic location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(rename = "countryCode", skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(rename = "countryName", skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

// Threat intelligence information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(rename = "providerName", skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    #[serde(rename = "reportLink", skip_serializing_if = "Option::is_none")]
    pub report_link: Option<String>,
    #[serde(rename = "threatDescription", skip_serializing_if = "Option::is_none")]
    pub threat_description: Option<String>,
    #[serde(rename = "threatName", skip_serializing_if = "Option::is_none")]
    pub threat_name: Option<String>,
    #[serde(rename = "threatType", skip_serializing_if = "Option::is_none")]
    pub threat_type: Option<String>,
}

// Malware entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<MalwareEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareEntityProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(rename = "fileEntityIds", skip_serializing_if = "Option::is_none")]
    pub file_entity_ids: Option<Vec<String>>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "malwareName", skip_serializing_if = "Option::is_none")]
    pub malware_name: Option<String>,
    #[serde(rename = "processEntityIds", skip_serializing_if = "Option::is_none")]
    pub process_entity_ids: Option<Vec<String>>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// Process entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<ProcessEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntityProperties {
    #[serde(rename = "accountEntityId", skip_serializing_if = "Option::is_none")]
    pub account_entity_id: Option<String>,
    #[serde(rename = "commandLine", skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(rename = "creationTimeUtc", skip_serializing_if = "Option::is_none")]
    pub creation_time_utc: Option<String>,
    #[serde(rename = "elevationToken", skip_serializing_if = "Option::is_none")]
    pub elevation_token: Option<ElevationToken>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "hostEntityId", skip_serializing_if = "Option::is_none")]
    pub host_entity_id: Option<String>,
    #[serde(
        rename = "hostLogonSessionEntityId",
        skip_serializing_if = "Option::is_none"
    )]
    pub host_logon_session_entity_id: Option<String>,
    #[serde(rename = "imageFileEntityId", skip_serializing_if = "Option::is_none")]
    pub image_file_entity_id: Option<String>,
    #[serde(
        rename = "parentProcessEntityId",
        skip_serializing_if = "Option::is_none"
    )]
    pub parent_process_entity_id: Option<String>,
    #[serde(rename = "processId", skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// Registry key entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryKeyEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<RegistryKeyEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryKeyEntityProperties {
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hive: Option<RegistryHive>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// Registry value entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValueEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<RegistryValueEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValueEntityProperties {
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "keyEntityId", skip_serializing_if = "Option::is_none")]
    pub key_entity_id: Option<String>,
    #[serde(rename = "valueData", skip_serializing_if = "Option::is_none")]
    pub value_data: Option<String>,
    #[serde(rename = "valueName", skip_serializing_if = "Option::is_none")]
    pub value_name: Option<String>,
    #[serde(rename = "valueType", skip_serializing_if = "Option::is_none")]
    pub value_type: Option<RegistryValueKind>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// Security group entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGroupEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SecurityGroupEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGroupEntityProperties {
    #[serde(rename = "distinguishedName", skip_serializing_if = "Option::is_none")]
    pub distinguished_name: Option<String>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "objectGuid", skip_serializing_if = "Option::is_none")]
    pub object_guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// URL entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<UrlEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlEntityProperties {
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// IoT device entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoTDeviceEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<IoTDeviceEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoTDeviceEntityProperties {
    #[serde(rename = "deviceId", skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(rename = "deviceName", skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(rename = "deviceType", skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    #[serde(rename = "edgeId", skip_serializing_if = "Option::is_none")]
    pub edge_id: Option<String>,
    #[serde(rename = "firmwareVersion", skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<String>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "hostEntityId", skip_serializing_if = "Option::is_none")]
    pub host_entity_id: Option<String>,
    #[serde(rename = "iotHubEntityId", skip_serializing_if = "Option::is_none")]
    pub iot_hub_entity_id: Option<String>,
    #[serde(rename = "iotSecurityAgentId", skip_serializing_if = "Option::is_none")]
    pub iot_security_agent_id: Option<String>,
    #[serde(rename = "ipAddressEntityId", skip_serializing_if = "Option::is_none")]
    pub ip_address_entity_id: Option<String>,
    #[serde(rename = "macAddress", skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(rename = "operatingSystem", skip_serializing_if = "Option::is_none")]
    pub operating_system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
    #[serde(rename = "serialNumber", skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(rename = "threatIntelligence", skip_serializing_if = "Option::is_none")]
    pub threat_intelligence: Option<Vec<ThreatIntelligence>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// Security alert entity (for entity list response)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlertEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SecurityAlertProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

// Bookmark entity (for entity list response)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HuntingBookmarkProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

// Mailbox entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<MailboxEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxEntityProperties {
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(
        rename = "externalDirectoryObjectId",
        skip_serializing_if = "Option::is_none"
    )]
    pub external_directory_object_id: Option<String>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(
        rename = "mailboxPrimaryAddress",
        skip_serializing_if = "Option::is_none"
    )]
    pub mailbox_primary_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upn: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// Mail cluster entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailClusterEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<MailClusterEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailClusterEntityProperties {
    #[serde(rename = "clusterGroup", skip_serializing_if = "Option::is_none")]
    pub cluster_group: Option<String>,
    #[serde(
        rename = "clusterQueryEndTime",
        skip_serializing_if = "Option::is_none"
    )]
    pub cluster_query_end_time: Option<String>,
    #[serde(
        rename = "clusterQueryStartTime",
        skip_serializing_if = "Option::is_none"
    )]
    pub cluster_query_start_time: Option<String>,
    #[serde(
        rename = "clusterSourceIdentifier",
        skip_serializing_if = "Option::is_none"
    )]
    pub cluster_source_identifier: Option<String>,
    #[serde(rename = "clusterSourceType", skip_serializing_if = "Option::is_none")]
    pub cluster_source_type: Option<String>,
    #[serde(
        rename = "countByDeliveryStatus",
        skip_serializing_if = "Option::is_none"
    )]
    pub count_by_delivery_status: Option<HashMap<String, serde_json::Value>>,
    #[serde(
        rename = "countByProtectionStatus",
        skip_serializing_if = "Option::is_none"
    )]
    pub count_by_protection_status: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "countByThreatType", skip_serializing_if = "Option::is_none")]
    pub count_by_threat_type: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "isVolumeAnomaly", skip_serializing_if = "Option::is_none")]
    pub is_volume_anomaly: Option<bool>,
    #[serde(rename = "mailCount", skip_serializing_if = "Option::is_none")]
    pub mail_count: Option<i32>,
    #[serde(rename = "networkMessageIds", skip_serializing_if = "Option::is_none")]
    pub network_message_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(rename = "queryTime", skip_serializing_if = "Option::is_none")]
    pub query_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threats: Option<Vec<String>>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// Mail message entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailMessageEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<MailMessageEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailMessageEntityProperties {
    #[serde(rename = "antispamDirection", skip_serializing_if = "Option::is_none")]
    pub antispam_direction: Option<AntispamMailDirection>,
    #[serde(
        rename = "bodyFingerprintBin1",
        skip_serializing_if = "Option::is_none"
    )]
    pub body_fingerprint_bin1: Option<i32>,
    #[serde(
        rename = "bodyFingerprintBin2",
        skip_serializing_if = "Option::is_none"
    )]
    pub body_fingerprint_bin2: Option<i32>,
    #[serde(
        rename = "bodyFingerprintBin3",
        skip_serializing_if = "Option::is_none"
    )]
    pub body_fingerprint_bin3: Option<i32>,
    #[serde(
        rename = "bodyFingerprintBin4",
        skip_serializing_if = "Option::is_none"
    )]
    pub body_fingerprint_bin4: Option<i32>,
    #[serde(
        rename = "bodyFingerprintBin5",
        skip_serializing_if = "Option::is_none"
    )]
    pub body_fingerprint_bin5: Option<i32>,
    #[serde(rename = "deliveryAction", skip_serializing_if = "Option::is_none")]
    pub delivery_action: Option<DeliveryAction>,
    #[serde(rename = "deliveryLocation", skip_serializing_if = "Option::is_none")]
    pub delivery_location: Option<DeliveryLocation>,
    #[serde(rename = "fileEntityIds", skip_serializing_if = "Option::is_none")]
    pub file_entity_ids: Option<Vec<String>>,
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "internetMessageId", skip_serializing_if = "Option::is_none")]
    pub internet_message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(rename = "networkMessageId", skip_serializing_if = "Option::is_none")]
    pub network_message_id: Option<String>,
    #[serde(rename = "p1Sender", skip_serializing_if = "Option::is_none")]
    pub p1_sender: Option<String>,
    #[serde(
        rename = "p1SenderDisplayName",
        skip_serializing_if = "Option::is_none"
    )]
    pub p1_sender_display_name: Option<String>,
    #[serde(rename = "p1SenderDomain", skip_serializing_if = "Option::is_none")]
    pub p1_sender_domain: Option<String>,
    #[serde(rename = "p2Sender", skip_serializing_if = "Option::is_none")]
    pub p2_sender: Option<String>,
    #[serde(
        rename = "p2SenderDisplayName",
        skip_serializing_if = "Option::is_none"
    )]
    pub p2_sender_display_name: Option<String>,
    #[serde(rename = "p2SenderDomain", skip_serializing_if = "Option::is_none")]
    pub p2_sender_domain: Option<String>,
    #[serde(rename = "receiveDate", skip_serializing_if = "Option::is_none")]
    pub receive_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    #[serde(rename = "senderIP", skip_serializing_if = "Option::is_none")]
    pub sender_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(
        rename = "threatDetectionMethods",
        skip_serializing_if = "Option::is_none"
    )]
    pub threat_detection_methods: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threats: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// Submission mail entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionMailEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SubmissionMailEntityProperties>,
    #[serde(rename = "systemData", skip_serializing_if = "Option::is_none")]
    pub system_data: Option<SystemData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionMailEntityProperties {
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "networkMessageId", skip_serializing_if = "Option::is_none")]
    pub network_message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    #[serde(rename = "reportType", skip_serializing_if = "Option::is_none")]
    pub report_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    #[serde(rename = "senderIp", skip_serializing_if = "Option::is_none")]
    pub sender_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "submissionDate", skip_serializing_if = "Option::is_none")]
    pub submission_date: Option<String>,
    #[serde(rename = "submissionId", skip_serializing_if = "Option::is_none")]
    pub submission_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submitter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<HashMap<String, serde_json::Value>>,
}

// ============================================================================
// PLAYBOOK STRUCTS
// ============================================================================

// Request body for triggering a playbook on an incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualTriggerRequestBody {
    #[serde(
        rename = "logicAppsResourceId",
        skip_serializing_if = "Option::is_none"
    )]
    pub logic_apps_resource_id: Option<String>,
    #[serde(rename = "tenantId", skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

// ============================================================================
// UTILITY STRUCTS
// ============================================================================

// Metadata pertaining to creation and last modification of the resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemData {
    #[serde(rename = "createdAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "createdBy", skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "createdByType", skip_serializing_if = "Option::is_none")]
    pub created_by_type: Option<CreatedByType>,
    #[serde(rename = "lastModifiedAt", skip_serializing_if = "Option::is_none")]
    pub last_modified_at: Option<String>,
    #[serde(rename = "lastModifiedBy", skip_serializing_if = "Option::is_none")]
    pub last_modified_by: Option<String>,
    #[serde(rename = "lastModifiedByType", skip_serializing_if = "Option::is_none")]
    pub last_modified_by_type: Option<CreatedByType>,
}

// Error response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudError {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CloudErrorBody>,
}

// Error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudErrorBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// Helpers

pub fn parse_incident_severity(s: &str) -> Result<IncidentSeverity> {
    match s {
        "High" => Ok(IncidentSeverity::High),
        "Medium" => Ok(IncidentSeverity::Medium),
        "Low" => Ok(IncidentSeverity::Low),
        "Informational" => Ok(IncidentSeverity::Informational),
        _ => Err(anyhow::anyhow!(
            "Invalid severity '{}'. Must be: High, Medium, Low, or Informational",
            s
        )),
    }
}

pub fn parse_incident_status(s: &str) -> Result<IncidentStatus> {
    match s {
        "New" => Ok(IncidentStatus::New),
        "Active" => Ok(IncidentStatus::Active),
        "Closed" => Ok(IncidentStatus::Closed),
        _ => Err(anyhow::anyhow!(
            "Invalid status '{}'. Must be: New, Active, or Closed",
            s
        )),
    }
}

pub fn parse_incident_classification(s: &str) -> Result<IncidentClassification> {
    match s {
        "Undetermined" => Ok(IncidentClassification::Undetermined),
        "TruePositive" => Ok(IncidentClassification::TruePositive),
        "BenignPositive" => Ok(IncidentClassification::BenignPositive),
        "FalsePositive" => Ok(IncidentClassification::FalsePositive),
        _ => Err(anyhow::anyhow!(
            "Invalid classification '{}'. Must be: Undetermined, TruePositive, BenignPositive, or FalsePositive",
            s
        )),
    }
}

pub fn parse_incident_classification_reason(s: &str) -> Result<IncidentClassificationReason> {
    match s {
        "SuspiciousActivity" => Ok(IncidentClassificationReason::SuspiciousActivity),
        "SuspiciousButExpected" => Ok(IncidentClassificationReason::SuspiciousButExpected),
        "IncorrectAlertLogic" => Ok(IncidentClassificationReason::IncorrectAlertLogic),
        "InaccurateData" => Ok(IncidentClassificationReason::InaccurateData),
        _ => Err(anyhow::anyhow!(
            "Invalid classification reason '{}'. Must be: SuspiciousActivity, SuspiciousButExpected, IncorrectAlertLogic, or InaccurateData",
            s
        )),
    }
}
