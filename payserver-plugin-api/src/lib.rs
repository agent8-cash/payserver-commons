//! The plugin manifest contract: parsing, id validation, and version
//! negotiation primitives shared by the plugin host and, eventually,
//! plugins themselves.
//!
//! This crate has no wasmtime dependency and instantiates nothing — the
//! runtime, action/filter dispatch, deadlines and trap handling are a
//! separate piece of work built on top of these types. What lives here is
//! everything that can be decided before a plugin's code ever runs: is the
//! manifest well-formed, is its id safe to route to, and does its declared
//! `ethpayserver` requirement match a candidate host version. The host-side
//! load-time gate that uses these types — refusing an incompatible plugin
//! and rejecting a duplicate id — lives in ethpayserver, since only the host
//! knows its own version and which plugins are already loaded.
//!
//! # Version negotiation
//!
//! The host presents itself as a dependency (`ethpayserver:^1.2.0`) the same
//! way one plugin would depend on another, so [`Dependency`] is the single
//! mechanism for both: a semver requirement matched against a semver
//! version, with [`Dependency::is_satisfied_by`] doing the check.

mod dependency;
mod failure_mode;
mod id;
mod kind;
mod manifest;
pub mod page;
mod slug;
mod standing_basis;

pub use dependency::{Dependency, InvalidDependency};
pub use failure_mode::FailureMode;
pub use id::{InvalidPluginId, PluginId};
pub use kind::PluginKind;
pub use manifest::{InvalidManifest, Manifest, PageDeclaration, PageIcon, PagePlacement};
pub use page::{
    Badge, Button, ButtonVariant, Card, Direction, Field, Fields, Figure, Form, Grid, Input,
    Notice, PageAction, PageActionResponse, PageElement, Row, Section, Select, Stack, Tab,
    Table, Tabs, Text, TextStyle, Tone, Viewer,
};
pub use slug::{InvalidSlug, PluginSlug, RESERVED_SLUGS};
pub use standing_basis::StandingBasis;

pub use semver::{Version, VersionReq};

/// Reachability is not the same as `pub`: an item can be `pub` in its module
/// and absent from this crate root's re-export list, so every in-crate test
/// would still pass by calling it through its in-crate path. This names the
/// page descriptor types exactly as a consumer (a plugin crate) would.
#[cfg(test)]
mod reachability {
    use crate::{Badge, Figure, PageAction, PageActionResponse, PageElement, Tone, Viewer};

    #[test]
    fn page_descriptor_types_are_reachable_from_the_crate_root() {
        let element = PageElement::Badge(Badge {
            text: "ok".to_string(),
            tone: Tone::Success,
        });
        assert!(matches!(element, PageElement::Badge(_)));
        assert_eq!(Viewer::Merchant, Viewer::Merchant);

        let figure = PageElement::Figure(Figure {
            label: "Active".to_string(),
            value: "210".to_string(),
            tone: Tone::Success,
        });
        assert!(matches!(figure, PageElement::Figure(_)));

        let action = PageAction {
            action_id: "test".to_string(),
            data: None,
        };
        assert_eq!(action.action_id, "test");

        let response = PageActionResponse {
            success: true,
            message: None,
            reason: None,
        };
        assert!(response.success);
    }
}
