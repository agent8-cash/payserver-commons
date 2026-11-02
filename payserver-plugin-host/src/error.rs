//! Why the host refused to register a plugin.

use payserver_plugin_api::{PluginId, Version, VersionReq};

/// A manifest the host refused to register.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PluginLoadError {
    /// The manifest never says what host it was built for.
    #[error("plugin {plugin_id} does not declare an ethpayserver dependency")]
    MissingHostDependency { plugin_id: PluginId },

    /// The manifest's `ethpayserver` requirement does not match this build.
    /// Names both sides so an admin knows what to change.
    #[error(
        "plugin {plugin_id} requires ethpayserver {requirement}, but this host is {host_version}"
    )]
    IncompatibleHost {
        plugin_id: PluginId,
        requirement: VersionReq,
        host_version: Version,
    },

    /// The manifest's version is below the floor configured for its id.
    #[error("plugin {plugin_id} version {actual} is below the minimum {minimum}")]
    BelowMinimumVersion {
        plugin_id: PluginId,
        minimum: Version,
        actual: Version,
    },

    /// Some other manifest already registered this id.
    #[error("plugin id {0} is already registered")]
    DuplicateId(PluginId),
}
