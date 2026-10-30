//! Common types shared across PayServer implementations.
//!
//! This crate provides data types used by payment servers that support
//! various blockchain networks (ethpayserver, and any future payserver on
//! another chain family).
//!
//! # Architecture
//!
//! - `ChainId`: CAIP-2 identifier for any chain, in any family
//! - `InvoiceData`, `PaymentData`: Generic data structures for invoices and payments
//! - Repository traits: `InvoiceRepository`, `PaymentRepository`, `WatchedAddressRepository`
//! - `Store`, `StoreRole`, `UserStore`: Multi-tenant store management
//! - Network-specific types (like ERC20 tokens) are defined in their respective PayServer crates

pub mod currency;
pub mod error;
pub mod repositories;
pub mod store;
pub mod traits;
pub mod types;

// Re-export commonly used types at the crate root for convenience.
pub use error::{PayServerError, PayServerResult};
pub use repositories::{
    CreateDeliveryParams,
    // Combined traits
    DataService,
    DataServiceReader,
    DataServiceWriter,
    // Invoice
    InvoiceQueryParams,
    InvoiceReader,
    InvoiceRepository,
    InvoiceWriter,
    // Live Watched Address (for evmmonitor/Redis)
    LiveWatchedAddressReader,
    LiveWatchedAddressRepository,
    LiveWatchedAddressWriter,
    // Payment Event
    PaymentEventWriter,
    // Payment Option
    PaymentOptionReader,
    PaymentOptionRepository,
    PaymentOptionWriter,
    // Payment
    PaymentQueryParams,
    PaymentReader,
    PaymentRepository,
    PaymentWriter,
    // Payout
    PayoutReader,
    PayoutRepository,
    PayoutWriter,
    // Refund
    RefundReader,
    RefundRepository,
    RefundWriter,
    // Errors
    RepositoryError,
    RepositoryResult,
    // Store Payment Method
    StorePaymentMethodReader,
    StorePaymentMethodRepository,
    StorePaymentMethodWriter,
    // Store Settings
    StoreSettingsReader,
    StoreSettingsRepository,
    StoreSettingsWriter,
    // Store Token Policy
    StoreTokenPolicyReader,
    StoreTokenPolicyRepository,
    StoreTokenPolicyWriter,
    // Store Webhook
    StoreWebhookReader,
    StoreWebhookRepository,
    StoreWebhookWriter,
    TokenPolicyEntryInput,
    // Token
    TokenQueryParams,
    TokenReader,
    TokenRepository,
    TokenWriter,
    // Watched Address (for PostgreSQL persistence)
    // Account Wallet
    WalletReader,
    WalletRepository,
    WalletWriter,
    WatchedAddressReader,
    WatchedAddressRepository,
    WatchedAddressWriter,
    // Webhook Delivery
    WebhookDeliveryReader,
    WebhookDeliveryRepository,
    WebhookDeliveryWriter,
};
pub use store::{Store, StoreId, StoreInfo};
pub use traits::{InvoiceData, InvoiceQuery, PaymentData};
pub use types::{
    AssetType, ChainId, ChainIdError, CleanupAddressInfo, DerivationAllocation, HealthStatus,
    InvoiceId, InvoiceStatus, NAMESPACE_BIP122, NAMESPACE_EIP155, NAMESPACE_MONERO,
    NAMESPACE_SOLANA, NAMESPACE_TRON, PaymentEvent, PaymentMethodId, PaymentOptionData,
    PaymentOptionId, PayoutData, PayoutStatus, PendingWatchInfo, RefundData, RefundStatus,
    StorePaymentMethod, StoreSettings, StoreTokenPolicy, StoreTokenPolicyEntry,
    StoreTokenPolicyWithEntries, StoreWebhook, TokenData, TokenPolicyMode, UserId, Wallet,
    WebhookDelivery, payment_request_uri,
};

#[cfg(test)]
mod root_reachability_tests {
    /// The CAIP-2 namespace constants are reachable by the path a consumer
    /// spells, not only by their in-crate one.
    ///
    /// They existed as `pub` in `types::chain` and were absent from the root
    /// re-export list above, so `types::NAMESPACE_TRON` did not resolve while
    /// every in-crate use of them compiled. A downstream crate scoping wallet
    /// resolution by namespace has to name these rather than retype the
    /// strings; a literal that drifts from the parser is a wallet that
    /// resolves for nothing.
    #[test]
    fn the_caip2_namespace_constants_are_reachable_from_the_crate_root() {
        assert_eq!(crate::NAMESPACE_EIP155, "eip155");
        assert_eq!(crate::NAMESPACE_TRON, "tron");

        // And they agree with what the parser reads back out of an identifier,
        // which is the only reason a constant is better than a literal.
        let tron = crate::ChainId::parse("tron:728126428").unwrap();
        assert_eq!(tron.namespace(), crate::NAMESPACE_TRON);
        assert_eq!(crate::ChainId::evm(1).namespace(), crate::NAMESPACE_EIP155);
    }
}
