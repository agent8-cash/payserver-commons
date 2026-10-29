//! API keys.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

/// API key info for list/get responses.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfoResponse {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    /// Per-key rate limit in requests per minute. Null = server default.
    pub rate_limit_rpm: Option<i32>,
    /// Set when the key is deprecated via rotation. Key remains valid during
    /// the grace window; null means not deprecated.
    pub deprecated_at: Option<DateTime<Utc>>,
    /// When the grace window ends for a deprecated key (computed server-side
    /// from `deprecated_at` + grace seconds). Null for non-deprecated keys.
    /// Surfacing this lets the client render the exact expiry without
    /// hardcoding the grace duration.
    pub deprecation_expires_at: Option<DateTime<Utc>>,
    /// Policy strings scoping the key, or `["unrestricted"]` for the owner's
    /// full role. Null means the key predates this field and inherits the
    /// owner's role in full, same as `["unrestricted"]`.
    pub permissions: Option<Vec<String>>,
}

/// Response for listing API keys.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyListResponse {
    pub keys: Vec<ApiKeyInfoResponse>,
}

/// Request to create a new API key.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiKeyPayload {
    /// Human-readable name for the key.
    pub name: String,
    /// Optional expiration time.
    pub expires_at: Option<DateTime<Utc>>,
    /// Policy strings to scope the key to, or `["unrestricted"]` for the
    /// owner's full role. `None` (field omitted) means the key inherits the
    /// owner's role in full — today's behaviour, so existing integrations
    /// are unaffected. `Some(vec![])` is a deliberate key that authenticates
    /// but can do nothing. `Some([..])` scopes the key to those policies.
    pub permissions: Option<Vec<String>>,
}

/// Response after creating an API key (includes plaintext key).
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiKeyResponsePayload {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    /// The plaintext API key. Store this securely — it cannot be retrieved again.
    pub key: String,
}

/// Response after rotating an API key.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateApiKeyResponsePayload {
    /// The new API key's ID.
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub created_at: DateTime<Utc>,
    /// The new plaintext API key. Store this securely.
    pub key: String,
    /// When the old key was deprecated (grace window starts here).
    pub old_key_deprecated_at: DateTime<Utc>,
    /// When the old key's grace window ends and it stops authenticating.
    /// Clients should show this directly instead of hardcoding "48 hours".
    pub old_key_grace_expires_at: DateTime<Utc>,
}

/// Request to update an API key's rate limit.
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateApiKeyPayload {
    /// Per-key rate limit in requests per minute. Null = use server default.
    pub rate_limit_rpm: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A create request that omits `permissions` entirely must deserialize
    /// to `None`, not to `Some(vec![])`: the two are distinct contracts
    /// (inherit the owner's role in full vs. a deliberately powerless key).
    #[test]
    fn omitted_permissions_on_create_is_none() {
        let payload: CreateApiKeyPayload =
            serde_json::from_str(r#"{"name": "test key", "expires_at": null}"#).unwrap();
        assert_eq!(payload.permissions, None);
    }

    /// An explicit empty array is a deliberate "can do nothing" key, and
    /// must not be conflated with the omitted-field case above.
    #[test]
    fn empty_permissions_on_create_is_some_empty() {
        let payload: CreateApiKeyPayload =
            serde_json::from_str(r#"{"name": "test key", "expires_at": null, "permissions": []}"#)
                .unwrap();
        assert_eq!(payload.permissions, Some(Vec::<String>::new()));
    }

    /// A non-empty array deserializes to the scoped policy list.
    #[test]
    fn scoped_permissions_on_create_is_some_with_values() {
        let payload: CreateApiKeyPayload = serde_json::from_str(
            r#"{"name": "test key", "expires_at": null, "permissions": ["x"]}"#,
        )
        .unwrap();
        assert_eq!(payload.permissions, Some(vec!["x".to_string()]));
    }

    /// A `CreateApiKeyPayload` with `permissions: None` round-trips through
    /// JSON as an explicit `null`, not as an omitted field (no
    /// `skip_serializing_if` is applied), so callers scanning the raw JSON
    /// see the key present.
    #[test]
    fn none_permissions_serializes_as_null() {
        let payload = CreateApiKeyPayload {
            name: "test key".to_string(),
            expires_at: None,
            permissions: None,
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["permissions"], serde_json::Value::Null);
    }

    /// A stored key response with no `permissions` column value must
    /// round-trip as `None`, distinct from `Some(vec![])`: the former means
    /// "inherits the owner's role in full" and the latter means "can do
    /// nothing".
    #[test]
    fn missing_permissions_on_response_is_none_not_empty() {
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000000",
            "name": "test key",
            "key_prefix": "pk_test",
            "is_active": true,
            "created_at": "2026-01-01T00:00:00Z",
            "last_used_at": null,
            "expires_at": null,
            "rate_limit_rpm": null,
            "deprecated_at": null,
            "deprecation_expires_at": null,
            "permissions": null
        }"#;
        let response: ApiKeyInfoResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.permissions, None);
    }
}
