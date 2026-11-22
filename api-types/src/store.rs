//! Stores, their payment methods, webhooks, settings and token policy.

use serde::{Deserialize, Serialize};

use crate::common::mask_xpub;
use types::{ChainId, StorePaymentMethod};
use uuid::Uuid;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

/// Store response.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreResponse {
    /// Store ID.
    pub id: Uuid,
    /// Store name.
    pub name: String,
    /// Website URL.
    pub website: Option<String>,
    /// Owner user ID.
    pub owner_id: Uuid,
    /// Whether the store is archived.
    #[serde(default)]
    pub archived: bool,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Request to create a new store.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateStoreRequest {
    /// Store name.
    pub name: String,
    /// Optional website URL.
    pub website: Option<String>,
}

/// Request to update a store.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateStoreRequest {
    /// New store name.
    pub name: Option<String>,
    /// New website URL.
    pub website: Option<String>,
}
/// Payment method response.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethodResponse {
    /// Payment method ID.
    pub id: Uuid,
    /// Store ID.
    pub store_id: Uuid,
    /// Chain ID.
    pub chain_id: ChainId,
    /// Token address (null for native asset).
    pub token_address: Option<String>,
    /// Asset symbol.
    pub asset_symbol: String,
    /// Extended public key of the wallet this method resolves to (masked).
    /// Null when nothing resolves - no pin, no store override, no account
    /// primary - which means the method cannot be paid yet.
    pub xpub_masked: Option<String>,
    /// Next derivation index on the resolved wallet. Null for the same reason.
    pub derivation_index: Option<i32>,
    /// Whether the payment method is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Request to create a payment method.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePaymentMethodRequest {
    /// Chain ID (e.g., 1 for Ethereum, 137 for Polygon, 11155111 for Sepolia).
    pub chain_id: ChainId,
    /// Token address for ERC20 tokens, null for native asset.
    pub token_address: Option<String>,
    /// Asset symbol (e.g., ETH, USDC).
    pub asset_symbol: String,
    /// Number of decimals for this asset (18 for ETH, 6 for USDC/USDT).
    pub decimals: u8,
    /// Extended **public** key to derive receive addresses from.
    ///
    /// Optional. Omitted means "use the key this store already resolves to" -
    /// the method's own pin, else the store's wallet, else the account primary.
    /// Supplying it is still allowed and pins the method to that key, creating
    /// the account wallet if it is new.
    ///
    /// Making this optional is what lets a merchant paste their key **once**.
    /// It used to be required, so the same 111-character string had to be
    /// retyped per chain, per token and per store, and every paste was another
    /// chance to fumble the value that decides where their money lands.
    ///
    /// It is a public key by construction: `validate_xpub` refuses an `xprv` on
    /// the version-byte prefix, so this can derive receive addresses and can
    /// never spend. That is what lets a merchant register with a passkey, paste
    /// a key, and take payments without ever identifying themselves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xpub: Option<String>,
}

/// Request to update a payment method.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePaymentMethodRequest {
    /// Enable or disable the payment method.
    pub enabled: Option<bool>,
    /// Update the xpub.
    pub xpub: Option<String>,
}
/// Webhook response.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookResponse {
    /// Webhook ID.
    pub id: Uuid,
    /// Store ID.
    pub store_id: Uuid,
    /// Webhook URL.
    pub webhook_url: String,
    /// Webhook secret (for signature verification).
    /// Only shown once when created/updated.
    pub webhook_secret: Option<String>,
    /// Whether the webhook is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Indicates if the webhook secret was rotated in this response.
    #[serde(default)]
    pub rotate_secret: bool,
    /// Last update timestamp.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Request to configure a webhook.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigureWebhookRequest {
    /// Webhook URL to receive notifications.
    pub webhook_url: String,
    /// Whether the webhook is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Request a new webhook secret. Omitted or false leaves the current secret in place.
    #[serde(default)]
    pub rotate_secret: bool,
}
/// Store settings response.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreSettingsResponse {
    pub store_id: Uuid,
    pub default_chain_id: Option<ChainId>,
    pub default_display_currency: Option<String>,
    pub logo_url: Option<String>,
    pub accent_color: Option<String>,
    pub notification_prefs: serde_json::Value,
    pub updated_at: String,
}

/// Request to update store settings (PATCH -- all fields optional).
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateStoreSettingsRequest {
    pub default_chain_id: Option<ChainId>,
    pub default_display_currency: Option<String>,
    pub logo_url: Option<String>,
    pub accent_color: Option<String>,
    pub notification_prefs: Option<serde_json::Value>,
}
/// Token policy response.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPolicyResponse {
    pub id: String,
    pub store_id: Uuid,
    pub mode: String,
    pub entries: Vec<TokenPolicyEntryPayload>,
    pub created_at: String,
    pub updated_at: String,
}

/// Token policy entry for API requests/responses.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPolicyEntryPayload {
    pub chain_id: ChainId,
    pub token_address: Option<String>,
    pub asset_symbol: String,
}

/// Request to set a token policy.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetTokenPolicyRequest {
    pub mode: String,
    pub entries: Vec<TokenPolicyEntryPayload>,
}
/// Store member response.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberResponse {
    /// User ID.
    pub user_id: Uuid,
    /// Store ID.
    pub store_id: Uuid,
    /// Role ID.
    pub role_id: Uuid,
    /// Role name.
    pub role_name: String,
    /// Role permissions.
    pub permissions: Vec<String>,
}

/// Request to add a member to a store.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddMemberRequest {
    /// User ID to add.
    pub user_id: Uuid,
    /// Role name (Owner, Manager, Employee, Guest).
    pub role: String,
}

/// Request to update a member's role.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateMemberRequest {
    /// New role name.
    pub role: String,
}

/// A webhook is enabled unless the caller says otherwise.
///
/// Absent means "on": configuring a webhook and having it silently not fire is
/// the worse failure.
fn default_enabled() -> bool {
    true
}

impl From<StorePaymentMethod> for PaymentMethodResponse {
    fn from(pm: StorePaymentMethod) -> Self {
        Self {
            id: pm.id,
            store_id: pm.store_id,
            chain_id: pm.chain_id,
            token_address: pm.token_address,
            asset_symbol: pm.asset_symbol,
            xpub_masked: pm.xpub.as_deref().map(mask_xpub),
            derivation_index: pm.derivation_index,
            enabled: pm.enabled,
            created_at: pm.created_at,
        }
    }
}
