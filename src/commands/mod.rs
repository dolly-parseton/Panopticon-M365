/*
    This is where I'll put all the commands.
    1. An API is not nessarily tied to a command, but commands will use APIs.
        * I'll almost surely do a simple 'loganalytics-query' command that uses the Azure Monitor API to run KQL queries against Log Analytics workspaces.
        * I'll also do some Sentinel specific commands that use the Sentinel APIs, maybe incident management commands.
        * (future) Some multi-API commands for complex tasks like account compromise remediation that use multiple APIs (Entra ID, Defender XDR, Sentinel, etc).
    2. Commands will implement the panopticon_core::prelude::Command trait so they can be used in pipelines, obvs.

    There's so many potentially useful commands.
*/
