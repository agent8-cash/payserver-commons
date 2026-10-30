//! Core data types shared across PayServer implementations.

use crate::store::StoreId;
use crate::types::ChainId;
use crate::types::{AssetType, InvoiceId, InvoiceStatus};

/// Query parameters for listing invoices.
#[derive(Debug, Clone, Default)]
pub struct InvoiceQuery {
    /// Filter by status.
    pub status: Option<InvoiceStatus>,
    /// Filter by currency.
    pub currency: Option<String>,
    /// Maximum number of results.
    pub limit: Option<u32>,
    /// Offset for pagination.
    pub offset: Option<u32>,
}

/// Generic invoice data returned by PayServers.
///
/// An invoice is network-agnostic: it represents a payment request in a
/// specific currency (which can be fiat like "USD" or crypto like "BTC").
/// The actual payment options (which chains/assets can be used to pay)
/// are stored separately in PaymentOptionData.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InvoiceData {
    pub id: InvoiceId,
    /// The store this invoice belongs to.
    pub store_id: StoreId,
    /// Invoice currency (e.g., "USD", "EUR", "BTC", "ETH").
    /// This is what the merchant prices in.
    pub currency: String,
    pub status: InvoiceStatus,
    /// Amount requested in the invoice currency.
    /// For fiat, this is a decimal string (e.g., "100.00").
    /// For crypto, this is in the smallest unit (e.g., wei for ETH).
    pub amount: String,
    /// Total amount received across all payment options, converted to invoice currency.
    /// This is calculated from payments and their exchange rates.
    pub amount_received: String,
    /// When the invoice was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the invoice expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Optional metadata.
    ///
    /// Merchant-supplied and unbounded - order ids, cart contents, notes,
    /// whatever the integration attaches. Nothing server-side interprets it,
    /// which is why it is the field slated to become end-to-end encrypted.
    /// Do not put anything here that the server needs to act on.
    pub metadata: Option<serde_json::Value>,
    /// Customer contact address, when the merchant supplied one.
    ///
    /// A first-class field rather than a key inside `metadata`. The
    /// server acts on this - it is what receipts are sent to - so it has to
    /// stay readable once `metadata` becomes ciphertext. It was previously
    /// derived by Postgres from `metadata->>'customer_email'`, which would have
    /// silently started returning NULL the moment that blob was encrypted,
    /// taking receipts with it and reporting nothing.
    ///
    /// The rule this encodes: if the server must act on a value, it is a
    /// declared field; if not, it belongs in `metadata`.
    pub customer_email: Option<String>,
    /// Optional extra data.
    pub extra: Option<serde_json::Value>,
}

/// Generic payment data returned by PayServers.
///
/// A payment is an actual received transaction. It belongs to an invoice
/// and optionally references the payment option that was used.
///
/// Note: Confirmations are computed dynamically as `current_block - block_number + 1`.
/// The `confirmed_at` timestamp indicates when the payment reached the required
/// confirmation threshold. If `confirmed_at` is None, the payment is still awaiting
/// confirmation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PaymentData {
    pub id: uuid::Uuid,
    pub invoice_id: InvoiceId,
    /// The payment option this payment was for (if known).
    pub payment_option_id: Option<uuid::Uuid>,
    /// EIP-155 chain ID where this payment was received.
    pub chain_id: ChainId,
    /// Asset type (native or ERC20).
    #[serde(default)]
    pub asset_type: AssetType,
    /// Amount received (smallest unit as string).
    pub amount: String,
    /// Asset symbol.
    pub asset_symbol: String,
    /// Token contract address (for ERC20 tokens).
    pub token_address: Option<String>,
    /// Transaction hash.
    pub tx_hash: String,
    /// Block number where the payment was included.
    /// Confirmations can be computed as: current_block - block_number + 1
    pub block_number: Option<u64>,
    /// When the payment was detected.
    pub detected_at: chrono::DateTime<chrono::Utc>,
    /// When the payment reached required confirmations (None = awaiting confirmation).
    pub confirmed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Sender address (if known).
    pub from_address: Option<String>,
    /// Whether this payment was invalidated by a chain reorganization.
    #[serde(default)]
    pub reorged: bool,
    /// Network-specific extra data.
    pub extra: Option<serde_json::Value>,

    // =========================================================================
    // Payment Aggregation Fields
    //
    // These fields enable aggregating payments across different assets/chains
    // into a single invoice total. Without these, we couldn't compare a payment
    // of 0.05 ETH against a $100 USD invoice.
    // =========================================================================
    /// The payment's value credited toward the invoice total, expressed in the
    /// invoice's currency.
    ///
    /// # Purpose
    ///
    /// Invoices can be denominated in any currency (USD, EUR, BTC, ETH, etc.),
    /// but payments arrive in specific assets (ETH on Ethereum, USDC on Polygon,
    /// etc.). This field converts each payment to the invoice's currency so they
    /// can be summed and compared against the invoice amount.
    ///
    /// # Calculation
    ///
    /// **Cross-currency payments** (e.g., USD invoice paid with ETH):
    /// ```text
    /// credited_amount = (raw_amount / 10^decimals) / rate
    ///
    /// Example: 50000000000000000 wei at rate 0.0005 ETH/USD
    ///   = (50000000000000000 / 10^18) / 0.0005
    ///   = 0.05 / 0.0005
    ///   = 100 USD
    /// ```
    ///
    /// **Same-asset payments** (e.g., ETH invoice paid with ETH):
    /// ```text
    /// credited_amount = raw_amount / 10^decimals
    ///
    /// Example: 1500000000000000000 wei
    ///   = 1500000000000000000 / 10^18
    ///   = 1.5 ETH
    /// ```
    ///
    /// # Important Behavior
    ///
    /// - **None means not counted**: Payments where conversion failed or the
    ///   payment option wasn't found are recorded for audit purposes but do NOT
    ///   count toward the invoice's `amount_received`.
    ///
    /// - **Rate is locked at invoice creation**: The exchange rate used comes
    ///   from `rate_used`, which was captured when the invoice was created.
    ///   Market fluctuations after invoice creation don't affect this value.
    ///
    /// - **Aggregation happens in the database**: A trigger sums all non-null
    ///   `credited_amount` values to update `invoice.amount_received`.
    pub credited_amount: Option<String>,

    /// Exchange rate used to calculate `credited_amount`.
    ///
    /// Format: `1 invoice_currency = rate asset_units`
    ///
    /// For example, if the invoice is in USD and payment is in ETH:
    /// - rate = "0.0005" means 1 USD = 0.0005 ETH
    ///
    /// This rate is captured at invoice creation time and locked in. It's stored
    /// here for auditability - you can verify how `credited_amount` was calculated.
    ///
    /// **None** for same-asset payments (no conversion needed).
    pub rate_used: Option<String>,

    /// When the rate was applied to calculate `credited_amount`.
    ///
    /// This is the timestamp when the payment was detected and converted,
    /// not when the rate was originally fetched (that's stored in the payment option).
    pub rate_applied_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invoice_query_default() {
        let query = InvoiceQuery::default();
        assert!(query.status.is_none());
        assert!(query.currency.is_none());
        assert!(query.limit.is_none());
        assert!(query.offset.is_none());
    }
}
