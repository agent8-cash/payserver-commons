//! Watched address repository traits.

use async_trait::async_trait;

use super::RepositoryResult;
use crate::types::ChainId;
use crate::types::{CleanupAddressInfo, InvoiceId, PaymentOptionId, PendingWatchInfo};

/// Read operations for watched addresses.
#[async_trait]
pub trait WatchedAddressReader: Send + Sync {
    /// Get the invoice ID associated with an address.
    async fn get_invoice_id(
        &self,
        address: &str,
        chain_id: &ChainId,
        token_address: Option<&str>,
    ) -> RepositoryResult<Option<InvoiceId>>;

    /// Get the payment option ID associated with an address.
    async fn get_payment_option_id(
        &self,
        address: &str,
        chain_id: &ChainId,
        token_address: Option<&str>,
    ) -> RepositoryResult<Option<PaymentOptionId>>;

    /// Get watched addresses pending notification to the monitor.
    async fn get_pending(&self) -> RepositoryResult<Vec<PendingWatchInfo>>;

    /// Get addresses for expired invoices past the grace period.
    ///
    /// Returns addresses where:
    /// - The watched address is still active
    /// - The associated invoice has status 'expired'
    /// - The invoice's expires_at + grace_period has passed
    async fn get_expired_for_cleanup(
        &self,
        grace_period_secs: i64,
    ) -> RepositoryResult<Vec<CleanupAddressInfo>>;

    /// Get addresses for paid invoices that are still being watched.
    async fn get_paid_for_cleanup(&self) -> RepositoryResult<Vec<CleanupAddressInfo>>;

    /// Get addresses for cancelled invoices that are still being watched.
    async fn get_cancelled_for_cleanup(&self) -> RepositoryResult<Vec<CleanupAddressInfo>>;
}

/// Write operations for watched addresses.
#[async_trait]
pub trait WatchedAddressWriter: Send + Sync {
    /// Insert or update a watched address for a payment option.
    async fn upsert(
        &self,
        address: &str,
        payment_option_id: &PaymentOptionId,
        chain_id: &ChainId,
        token_address: Option<&str>,
    ) -> RepositoryResult<()>;

    /// Mark a watched address as notified to the monitor.
    async fn mark_notified(
        &self,
        address: &str,
        chain_id: &ChainId,
        token_address: Option<&str>,
    ) -> RepositoryResult<()>;

    /// Deactivate a watched address (set is_active = false).
    ///
    /// Returns true if an address was deactivated, false if not found or already inactive.
    async fn deactivate(
        &self,
        address: &str,
        chain_id: &ChainId,
        token_address: Option<&str>,
    ) -> RepositoryResult<bool>;

    /// Deactivate all watched addresses for a payment option.
    async fn deactivate_for_payment_option(
        &self,
        payment_option_id: &PaymentOptionId,
    ) -> RepositoryResult<u64>;
}

/// Combined watched address repository with full read/write access.
pub trait WatchedAddressRepository: WatchedAddressReader + WatchedAddressWriter {}

/// Blanket implementation for any type implementing both Reader and Writer.
impl<T: WatchedAddressReader + WatchedAddressWriter> WatchedAddressRepository for T {}
