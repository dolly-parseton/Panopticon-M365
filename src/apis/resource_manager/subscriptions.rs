use crate::api_resource;

use super::ResourceManager;
use crate::types::azure::resource_manager::{raw, Subscription};

api_resource! {
    Subscriptions on ResourceManager {
        list list()
            -> Vec<Subscription> from raw::SubscriptionResponse
            at "subscriptions?api-version=2022-12-01";
    }
}
