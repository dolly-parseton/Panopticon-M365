/*
    What does this library do?
    * Contains utility types that support API requests to various security related M365 services.
        * Azure Sentinel and associated APIs - KQL Queries, Incidents, Alerts, Watchlists, etc.
        * Microsoft Defender XDR (Microsoft Graph APIs) - KQL Queries
        * (future) Entra ID and Identity Protection APIs - Risk Events, Risk Detections, Revoke Sessions, Reset Password, etc.
    * Command Types with the panopticon-core trait implementations, allowing for execution in panopticon_core::prelude::Pipeline.
*/

mod apis; // Contains API request/response types and logic for various M365 related APIs.
mod client; // Contains the HTTP client type that handles auth, requests, responses, etc.
mod commands; // Contains command types that implement panopticon_core::prelude::Command for use in pipelines.
mod types; // Contains utility types used across the library.

/*
    TODO:
    1. First sort the client and the interface used to make requests.
        * I want to make this as safe and constrained as possible to avoid runtime errors.
        * Additionally, if I go about adding scary remediation commands I need to consider 'safety' a bit more holistically and consider halts/approvals and how the execution flow looks to enable that.
        * Maybe worth considering a 'restrictions' system that can be applied to clients/commands to limit their scope of action? (e.g. read-only, no user-impacting actions, etc)
    2. Then add API support for strictly the Azure Monitor Query route.
        * At this point client should be able to auth.
        * I've already got kql-language-tools for KQL parsing/validation (some bits to revist and finish there, api needs some work)
    3. Then add a command that exposes a way to run a KQL query against a Log Analytics workspace.
        * Might be worth doing multiple-queries
        * Needs to think about formatting and data normalisation methods that might be needed to make the query results readily consumable in pipelines.
    4. At this point there's a few things to consider:
        * Azure KeyVault support for storing client secrets securely, authenticate as a user to KV then as an app to the APIs from here. Once we've done the above I think this is absolutely required.
        * Azure query pack support for the query command, users can reference a query pack query. I don't see a nice way to handle parameters/tera templating with these but could be interesting to explore. https://learn.microsoft.com/en-us/rest/api/loganalytics/query-packs?view=rest-loganalytics-2025-07-01
        * Azure Store Account support for writing tabular data to storage accounts directly from queries. Could be interesting for large data sets that need to be processed later in pipelines. https://learn.microsoft.com/en-us/rest/api/loganalytics/queries/create-storage-account-connection?view=rest-loganalytics-2025-07-01
            If we're doing writing reading also would make sense.
        * Azure Sentinel Watchlist API cover then a command for interacting with watchlists, there's a crazy amount of potential functionality here, query -> update watchlist -> alert rules -> incidents -> playbooks, etc.
            Quickly adjust the scope of a detection by running queries -> transformating data -> updating watchlists that detection rules reference.
        * Microsoft Defender XDR KQL query support, similar to Azure Monitor Query but via the 'newish' Graph API endpoints for Defender XDR.
            This maybe could be higher in the priority list given the July 2026 deprecation of the Sentinel UI, APIs will remain but I'd rather avoid having to use Defender XDR lol.
        * Alot of very useful Entra ID APIs around risk detections/events, user session revocation, password resets, etc.
            Could be very useful for automating response to identity threats.
        * Alot of very useful Defender for Office 365 APIs for email actions, I'd be thrilled to bypass the most painful part of the XDR portal

    Steps 1 to 3 are straight forward enough, need to properly define a scope for everything that comes after.
    I also note this is another library and I've yet to make any sort of interface for authoring pipelines that use these commands, might repurpose a bunch of the old kql-panopticon TUI and REPL bits.
*/
