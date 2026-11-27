//! Payments, refunds and payouts.

use serde::{Deserialize, Serialize};

use crate::invoice::InvoiceResponse;
use chrono::Utc;
use types::{ChainId, PaymentData, PayoutData, RefundData};
use uuid::Uuid;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

/// Payment response.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResponse {
    /// Payment ID.
    pub id: String,
    /// Store the payment's invoice belongs to (list endpoints only).
    pub store_id: Option<String>,
    /// Store name (list endpoints only) — see [`InvoiceResponse::store_name`].
    pub store_name: Option<String>,
    /// Chain ID (EIP-155).
    pub chain_id: ChainId,
    /// Invoice ID this payment belongs to.
    pub invoice_id: String,
    /// Transaction hash.
    pub tx_hash: String,
    /// Amount received.
    pub amount: String,
    /// Asset symbol.
    pub asset_symbol: String,
    /// Token contract address (for ERC20).
    pub token_address: Option<String>,
    /// Block number.
    pub block_number: Option<u64>,
    /// Sender address.
    pub from_address: Option<String>,
    /// When the payment was detected.
    pub detected_at: chrono::DateTime<chrono::Utc>,
    /// When the payment was confirmed (None = awaiting confirmation).
    pub confirmed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether this payment was invalidated by a chain reorg.
    #[serde(default)]
    pub reorged: bool,
    /// Token decimals (for display formatting).
    #[serde(default = "default_decimals")]
    pub decimals: u8,
}

/// Paginated payment list response.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentListResponse {
    /// Total number of matching payments.
    pub total: i64,
    /// Payments in this page.
    pub payments: Vec<PaymentResponse>,
}

/// Refund response.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    pub id: Uuid,
    pub invoice_id: String,
    pub payment_id: Uuid,
    pub to_address: String,
    pub chain_id: ChainId,
    pub asset_type: String,
    pub asset_symbol: String,
    pub amount: String,
    pub tx_hash: Option<String>,
    pub status: String,
    pub fee_amount: Option<String>,
    pub reason: Option<String>,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub confirmed_at: Option<chrono::DateTime<Utc>>,
}

/// Request body for creating a refund.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRefundRequest {
    /// Optional partial refund amount (in smallest unit).
    /// If omitted, refunds the full payment amount.
    pub amount: Option<String>,
    /// Reason for the refund.
    pub reason: Option<String>,
}
/// Payout response.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutResponse {
    pub id: Uuid,
    pub store_id: Uuid,
    pub invoice_ids: Vec<String>,
    pub destination_address: String,
    pub chain_id: ChainId,
    pub asset_type: String,
    pub asset_symbol: String,
    pub amount: String,
    pub tx_hash: Option<String>,
    pub status: String,
    pub fee_amount: Option<String>,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub confirmed_at: Option<chrono::DateTime<Utc>>,
}

/// Payout list response with pagination.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutListResponse {
    pub total: i64,
    pub payouts: Vec<PayoutResponse>,
}

/// Request body for creating a payout.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePayoutRequest {
    /// Invoice IDs to include in this payout.
    /// If empty, sweeps all settled invoices.
    pub invoice_ids: Vec<String>,
    /// Destination wallet address.
    pub destination_address: String,
    /// EIP-155 chain ID to sweep from.
    pub chain_id: ChainId,
    /// Asset symbol to sweep (e.g., "ETH", "USDC").
    pub asset_symbol: String,
    /// Token contract address (required for ERC20 payouts).
    pub token_address: Option<String>,
}
/// Response for tx hash lookup — returns the matching invoice and payment.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxHashLookupResponse {
    /// The invoice linked to this transaction.
    pub invoice: InvoiceResponse,
    /// The payment matching the tx hash.
    pub payment: PaymentResponse,
}

impl From<PaymentData> for PaymentResponse {
    fn from(p: PaymentData) -> Self {
        let decimals = token_decimals(&p.asset_symbol, p.token_address.as_deref());
        Self {
            id: p.id.to_string(),
            // Payments carry no store of their own; only the list endpoint,
            // which already resolves the invoice, fills these in.
            store_id: None,
            store_name: None,
            chain_id: p.chain_id,
            invoice_id: p.invoice_id.0,
            tx_hash: p.tx_hash,
            amount: p.amount,
            asset_symbol: p.asset_symbol,
            token_address: p.token_address,
            block_number: p.block_number,
            from_address: p.from_address,
            detected_at: p.detected_at,
            confirmed_at: p.confirmed_at,
            reorged: p.reorged,
            decimals,
        }
    }
}

impl From<RefundData> for RefundResponse {
    fn from(r: RefundData) -> Self {
        Self {
            id: r.id,
            invoice_id: r.invoice_id.0,
            payment_id: r.payment_id,
            to_address: r.to_address,
            chain_id: r.chain_id,
            asset_type: r.asset_type,
            asset_symbol: r.asset_symbol,
            amount: r.amount,
            tx_hash: r.tx_hash,
            status: r.status.to_string(),
            fee_amount: r.fee_amount,
            reason: r.reason,
            error_message: r.error_message,
            created_at: r.created_at,
            confirmed_at: r.confirmed_at,
        }
    }
}

impl From<PayoutData> for PayoutResponse {
    fn from(p: PayoutData) -> Self {
        Self {
            id: p.id,
            store_id: p.store_id.0,
            invoice_ids: p.invoice_ids,
            destination_address: p.destination_address,
            chain_id: p.chain_id,
            asset_type: p.asset_type,
            asset_symbol: p.asset_symbol,
            amount: p.amount,
            tx_hash: p.tx_hash,
            status: p.status.to_string(),
            fee_amount: p.fee_amount,
            error_message: p.error_message,
            created_at: p.created_at,
            confirmed_at: p.confirmed_at,
        }
    }
}

/// Resolve token decimals from symbol and optional contract address.
pub(crate) fn token_decimals(symbol: &str, token_address: Option<&str>) -> u8 {
    match symbol {
        "ETH" | "POL" | "MATIC" | "FTM" | "xDAI" | "DAI" | "WETH" => 18,
        "USDC" | "USDT" => 6,
        "WBTC" => 8,
        _ => {
            // ERC20 without a known symbol — check well-known contract addresses.
            if let Some(addr) = token_address {
                let addr_lower = addr.to_lowercase();
                // USDC on major chains
                if addr_lower == "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
                    || addr_lower == "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"
                    || addr_lower == "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"
                {
                    return 6;
                }
                // WBTC on Ethereum
                if addr_lower == "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599" {
                    return 8;
                }
            }
            18 // default to 18 for unknown tokens
        }
    }
}

/// Most assets this system handles are 18-decimal.
///
/// A default at all is deliberate: client and server deploy separately, so a
/// response from an older server that omits this must still render rather than
/// failing the whole list parse.
fn default_decimals() -> u8 {
    18
}
