use crate::api_resource;

use super::SentinelWorkspace;
use crate::types::azure::sentinel::{raw, CreateWatchlistItem, WatchlistItem};

api_resource! {
    WatchlistItems on SentinelWorkspace {
        list list(watchlist_alias: &str)
            -> Vec<WatchlistItem> from raw::WatchlistItemResponse
            at "watchlists/{watchlist_alias}/watchlistItems";

        get get(watchlist_alias: &str, watchlist_item_id: &str)
            -> WatchlistItem from raw::WatchlistItemResponse
            at "watchlists/{watchlist_alias}/watchlistItems/{watchlist_item_id}";

        put create_or_update(watchlist_alias: &str, watchlist_item_id: &str)
            -> WatchlistItem from raw::WatchlistItemResponse
            at "watchlists/{watchlist_alias}/watchlistItems/{watchlist_item_id}"
            with body: &CreateWatchlistItem;

        delete delete(watchlist_alias: &str, watchlist_item_id: &str)
            at "watchlists/{watchlist_alias}/watchlistItems/{watchlist_item_id}";
    }
}
