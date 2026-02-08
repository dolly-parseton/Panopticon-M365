use crate::api_resource;

use super::SentinelWorkspace;
use crate::types::azure::sentinel::{raw, CreateWatchlist, Watchlist};

api_resource! {
    Watchlists on SentinelWorkspace {
        list list()
            -> Vec<Watchlist> from raw::WatchlistResponse
            at "watchlists";

        get get(watchlist_alias: &str)
            -> Watchlist from raw::WatchlistResponse
            at "watchlists/{watchlist_alias}";

        put create_or_update(watchlist_alias: &str)
            -> Watchlist from raw::WatchlistResponse
            at "watchlists/{watchlist_alias}"
            with body: &CreateWatchlist;

        delete delete(watchlist_alias: &str)
            at "watchlists/{watchlist_alias}";
    }
}
