use panopticon_core::extend::Extension;
use std::collections::HashMap;
use std::sync::Arc;

/// Core trait for any M365/Azure resource that can be targeted by operations.
///
/// Resources carry their identity, auth context, and support multi-key resolution
/// so pipeline authors can reference them by user-defined label, resource-specific
/// IDs (e.g. workspace GUID), or full ARM paths.
pub trait M365Resource: Clone + Send + Sync + 'static {
    /// Primary identifier (e.g. ARM resource path).
    fn id(&self) -> &str;

    /// All keys this resource can be resolved by.
    /// Should include `id()` plus any resource-specific identifiers
    /// (workspace GUID, user label, etc.).
    fn resolve_keys(&self) -> Vec<&str>;

    /// Client ID used to authenticate requests to this resource.
    fn client_id(&self) -> &str;

    /// Tenant ID this resource belongs to.
    fn tenant_id(&self) -> &str;

    /// Default OAuth2 scope for most endpoints on this resource.
    /// Endpoints can override this via `Endpoint::auth_scope()`.
    fn default_scope() -> &'static str
    where
        Self: Sized;
}

/// Extension trait for Azure ARM resources that live under a subscription/resource group.
pub trait AzureResource: M365Resource {
    fn subscription_id(&self) -> &str;
    fn resource_group(&self) -> &str;

    /// Full ARM resource path.
    fn resource_path(&self) -> &str {
        self.id()
    }
}

/// A typed, multi-key indexed collection of resources.
///
/// Registered as a pipeline extension (one per resource type).
/// Supports resolution by any key a resource exposes via `resolve_keys()`,
/// plus optional user-defined labels added via `insert_labeled()`.
pub struct ResourceMap<T: M365Resource> {
    resources: Vec<T>,
    index: HashMap<String, usize>,
}

impl<T: M365Resource> Default for ResourceMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: M365Resource> Clone for ResourceMap<T> {
    fn clone(&self) -> Self {
        Self {
            resources: self.resources.clone(),
            index: self.index.clone(),
        }
    }
}

impl<T: M365Resource> Extension for ResourceMap<T> {}

impl<T: M365Resource> ResourceMap<T> {
    pub fn new() -> Self {
        Self {
            resources: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// Insert a resource, indexing all its resolve keys.
    pub fn insert(&mut self, resource: T) {
        let idx = self.resources.len();
        for key in resource.resolve_keys() {
            self.index.insert(key.to_string(), idx);
        }
        self.resources.push(resource);
    }

    /// Insert a resource with an additional user-defined label.
    pub fn insert_labeled(&mut self, label: &str, resource: T) {
        let idx = self.resources.len();
        self.index.insert(label.to_string(), idx);
        for key in resource.resolve_keys() {
            self.index.insert(key.to_string(), idx);
        }
        self.resources.push(resource);
    }

    /// Resolve a resource by any indexed key (label, ID, resource-specific identifier).
    pub fn resolve(&self, key: &str) -> Option<&T> {
        let idx = self.index.get(key)?;
        self.resources.get(*idx)
    }

    /// Get all resources in this map.
    pub fn all(&self) -> &[T] {
        &self.resources
    }

    /// Number of resources in this map.
    pub fn len(&self) -> usize {
        self.resources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct TestResource {
        id: String,
        workspace_id: String,
        label: Option<String>,
        client_id: String,
        tenant_id: String,
    }

    impl M365Resource for TestResource {
        fn id(&self) -> &str {
            &self.id
        }

        fn resolve_keys(&self) -> Vec<&str> {
            let mut keys = vec![self.id.as_str(), self.workspace_id.as_str()];
            if let Some(label) = &self.label {
                keys.push(label.as_str());
            }
            keys
        }

        fn client_id(&self) -> &str {
            &self.client_id
        }

        fn tenant_id(&self) -> &str {
            &self.tenant_id
        }

        fn default_scope() -> &'static str {
            "https://api.example.com/.default"
        }
    }

    #[test]
    fn resolve_by_id() {
        let mut map = ResourceMap::new();
        map.insert(TestResource {
            id: "/subscriptions/sub1/resourceGroups/rg1/providers/X/ws1".into(),
            workspace_id: "abc-123".into(),
            label: None,
            client_id: "client".into(),
            tenant_id: "tenant".into(),
        });

        assert!(map
            .resolve("/subscriptions/sub1/resourceGroups/rg1/providers/X/ws1")
            .is_some());
    }

    #[test]
    fn resolve_by_workspace_id() {
        let mut map = ResourceMap::new();
        map.insert(TestResource {
            id: "/subscriptions/sub1/resourceGroups/rg1/providers/X/ws1".into(),
            workspace_id: "abc-123".into(),
            label: None,
            client_id: "client".into(),
            tenant_id: "tenant".into(),
        });

        let res = map.resolve("abc-123").unwrap();
        assert_eq!(res.workspace_id, "abc-123");
    }

    #[test]
    fn resolve_by_label() {
        let mut map = ResourceMap::new();
        map.insert_labeled(
            "prod-soc",
            TestResource {
                id: "/subscriptions/sub1/resourceGroups/rg1/providers/X/ws1".into(),
                workspace_id: "abc-123".into(),
                label: None,
                client_id: "client".into(),
                tenant_id: "tenant".into(),
            },
        );

        let res = map.resolve("prod-soc").unwrap();
        assert_eq!(res.workspace_id, "abc-123");
    }

    #[test]
    fn resolve_missing_returns_none() {
        let map = ResourceMap::<TestResource>::new();
        assert!(map.resolve("nonexistent").is_none());
    }

    #[test]
    fn multiple_resources() {
        let mut map = ResourceMap::new();
        map.insert_labeled(
            "prod",
            TestResource {
                id: "id1".into(),
                workspace_id: "ws1".into(),
                label: None,
                client_id: "c1".into(),
                tenant_id: "t1".into(),
            },
        );
        map.insert_labeled(
            "staging",
            TestResource {
                id: "id2".into(),
                workspace_id: "ws2".into(),
                label: None,
                client_id: "c2".into(),
                tenant_id: "t2".into(),
            },
        );

        assert_eq!(map.resolve("prod").unwrap().tenant_id, "t1");
        assert_eq!(map.resolve("ws2").unwrap().tenant_id, "t2");
        assert_eq!(map.all().len(), 2);
    }
}
