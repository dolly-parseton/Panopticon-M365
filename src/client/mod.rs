/*
    To make all the requests simple I should make a unified HTTP client that handles all the auth token refreshing and stuff.
    I should define a few things
    * Client (struct) - holds the HTTP client, auth tokens, config, etc.
        * If we allow multi-tenant clients it'll need some kind of per-tenant token storage and interface for adding new tenants, therefore it'll also need a tenant type and I'll want to find some APIs for identifying tenants.

    * ClientConfig (struct) - holds config data for the client (consumed on Client creation, might need a builder?)
    * IntoRequest (trait) - something that can be converted into an HTTP request (with auth headers, etc), nice interface for making requests and adding safety to them. Impl per API request type.
        * There's an opportunity here for a factory/generic request type that can be used to enable nextLink handling and other common API request patterns.
    * FromResponse (trait) - something that can be created from an HTTP response, nice interface for handling responses. Impl per API response type.
    * ??? - Some kind of interface for response handling.

    Some open questions:
    * Should a single client be able to make requests to multiple tenants? Don't see why not if auth tokens are stored per-tenant and the requests specify tenant (given the application for this I think that's fair).
    * Should the client be generic over the HTTP client implementation? Would let crate users pick their own HTTP client, would be fun to implement something like that.

    Seems like the client is a big bit of work but the more I do here the easier it'll be to add new API support and then build commands on top of that.
*/
