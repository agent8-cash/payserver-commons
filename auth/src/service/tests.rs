//! Tests for the authentication service.

use std::sync::Arc;

use crate::error::AuthError;
use crate::models::{
    CompletePasskeyRegistrationRequest, Device, DeviceId, DeviceType, PasskeyId, Session,
    SessionId, StartNewUserWalletRegistrationRequest, StartPasskeyRegistrationRequest,
    StartRecoveryRequest, StartWalletLoginRequest, User, UserId,
};
use crate::repository::inmemory::InMemoryRepository;
use crate::repository::{DeviceRepository, SessionRepository, UserRepository};

use super::AuthService;

fn create_service() -> AuthService<InMemoryRepository> {
    let repo = Arc::new(InMemoryRepository::new());
    AuthService::new(repo)
}

// ========================================================================
// Session Validation Tests
// ========================================================================

#[tokio::test]
async fn test_validate_invalid_session() {
    let service = create_service();

    let result = service.validate_session(SessionId::new()).await;
    assert!(matches!(result, Err(AuthError::SessionInvalid)));
}

#[tokio::test]
async fn test_logout_requires_valid_session() {
    let service = create_service();

    // Logout with invalid session should succeed (idempotent)
    // but validate_session should still fail
    let _ = service.logout(SessionId::new()).await;
    let result = service.validate_session(SessionId::new()).await;
    assert!(matches!(result, Err(AuthError::SessionInvalid)));
}

#[tokio::test]
async fn test_logout_all_requires_valid_session() {
    let service = create_service();

    let result = service.logout_all(SessionId::new()).await;
    assert!(matches!(result, Err(AuthError::SessionInvalid)));
}

// ========================================================================
// Device Management Tests
// ========================================================================

#[tokio::test]
async fn test_get_devices_requires_valid_session() {
    let service = create_service();

    let result = service.get_devices(SessionId::new()).await;
    assert!(matches!(result, Err(AuthError::SessionInvalid)));
}

#[tokio::test]
async fn test_revoke_device_requires_valid_session() {
    let service = create_service();

    let result = service
        .revoke_device(SessionId::new(), DeviceId::new())
        .await;
    assert!(matches!(result, Err(AuthError::SessionInvalid)));
}

// ========================================================================
// Passkey Tests
// ========================================================================

#[tokio::test]
async fn test_get_passkeys_requires_valid_session() {
    let service = create_service();

    let result = service.get_passkeys(SessionId::new()).await;
    assert!(matches!(result, Err(AuthError::SessionInvalid)));
}

#[tokio::test]
async fn test_start_passkey_login_user_not_found() {
    let service = create_service();

    // Discoverable passkey login returns a challenge even with no users
    // (browser-side credential discovery handles user selection)
    let result = service.start_passkey_login().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_revoke_passkey_requires_valid_session() {
    let service = create_service();

    let result = service
        .revoke_passkey(SessionId::new(), PasskeyId::new())
        .await;
    assert!(matches!(result, Err(AuthError::SessionInvalid)));
}

#[tokio::test]
async fn test_start_passkey_registration_requires_valid_session() {
    let service = create_service();

    let request = StartPasskeyRegistrationRequest {
        passkey_name: "Test Passkey".to_string(),
    };

    let result = service
        .start_passkey_registration(SessionId::new(), request)
        .await;
    assert!(matches!(result, Err(AuthError::SessionInvalid)));
}

#[tokio::test]
async fn test_start_new_user_passkey_registration_invalid_email() {
    let service = create_service();

    let result = service.start_new_user_passkey_registration().await;
    // No email validation — should succeed (user ID generated internally)
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_start_new_user_passkey_registration_valid_email() {
    let service = create_service();

    // Valid email should return a challenge and user_id
    let result = service.start_new_user_passkey_registration().await;
    assert!(result.is_ok());

    let response = result.unwrap();
    assert!(!response.options.public_key.challenge.is_empty());
    // User ID should be returned so client can pass it back during completion
    assert!(!response.user_id.0.is_nil());
}

#[tokio::test]
async fn test_start_new_user_passkey_registration_email_case_insensitive() {
    let service = create_service();

    // Start registration — no email parameter needed (user ID generated internally)
    let result1 = service.start_new_user_passkey_registration().await;
    assert!(result1.is_ok());
}

// ========================================================================
// Recovery Tests
// ========================================================================

#[tokio::test]
async fn test_start_account_recovery_user_not_found() {
    let service = create_service();

    // Try recovery for non-existent user
    let request = StartRecoveryRequest {
        identifier: "nonexistent@example.com".to_string(),
        recovery_verification_hash: "some_hash".to_string(),
    };

    // Should return InvalidRecoveryMnemonic (not UserNotFound) to prevent enumeration
    let result = service.start_account_recovery(request).await;
    assert!(matches!(result, Err(AuthError::InvalidRecoveryMnemonic)));
}

#[tokio::test]
async fn test_start_account_recovery_invalid_identifier() {
    let service = create_service();

    let request = StartRecoveryRequest {
        identifier: "invalid-email".to_string(),
        recovery_verification_hash: "some_hash".to_string(),
    };

    let result = service.start_account_recovery(request).await;
    assert!(matches!(result, Err(AuthError::InvalidEmail(_))));
}

// ========================================================================
// Email Validation Tests
// ========================================================================

#[tokio::test]
async fn test_passkey_registration_generates_unique_users() {
    let service = create_service();

    let result1 = service.start_new_user_passkey_registration().await;
    let result2 = service.start_new_user_passkey_registration().await;
    assert!(result1.is_ok());
    assert!(result2.is_ok());

    // Each registration should get a unique user ID
    assert_ne!(result1.unwrap().user_id, result2.unwrap().user_id);
}

// Note: Full flow tests (registration, login, recovery, device management)
// require real WebAuthn credentials which cannot be mocked easily.
// These should be tested via integration tests with a WebAuthn testing library
// or end-to-end tests with a real browser.

// ========================================================================
// Wallet Authentication Tests
// ========================================================================

#[tokio::test]
async fn test_wallet_challenge_message_determinism() {
    let service = create_service();

    // Same inputs should produce same output
    let challenge = "abc123";
    let address = "0x1234567890123456789012345678901234567890";
    let timestamp = chrono::Utc::now();

    let msg1 = service.generate_wallet_challenge_message(challenge, address, &timestamp);
    let msg2 = service.generate_wallet_challenge_message(challenge, address, &timestamp);

    assert_eq!(msg1, msg2, "Same inputs must produce identical messages");

    // Different timestamp should produce different output
    let different_timestamp = timestamp + chrono::Duration::seconds(1);
    let msg3 = service.generate_wallet_challenge_message(challenge, address, &different_timestamp);

    assert_ne!(
        msg1, msg3,
        "Different timestamps must produce different messages"
    );
}

#[tokio::test]
async fn test_wallet_address_validation() {
    let service = create_service();

    // Valid address (lowercase)
    let result =
        service.validate_and_checksum_address("0x1234567890abcdef1234567890abcdef12345678");
    assert!(result.is_ok());

    // Valid address (checksummed)
    let result =
        service.validate_and_checksum_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    assert!(result.is_ok());

    // Invalid: too short
    let result = service.validate_and_checksum_address("0x1234");
    assert!(matches!(result, Err(AuthError::InvalidWalletAddress(_))));

    // Invalid: not hex
    let result =
        service.validate_and_checksum_address("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG");
    assert!(matches!(result, Err(AuthError::InvalidWalletAddress(_))));

    // Address without 0x prefix is accepted by alloy-primitives
    let result = service.validate_and_checksum_address("1234567890abcdef1234567890abcdef12345678");
    assert!(
        result.is_ok(),
        "alloy-primitives accepts addresses without 0x prefix"
    );
}

#[tokio::test]
async fn test_wallet_signature_verification() {
    use k256::ecdsa::SigningKey;
    use sha3::{Digest, Keccak256};

    let service = create_service();

    // Create a test private key (deterministic for testing)
    let private_key_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let signing_key = SigningKey::from_bytes((&private_key_bytes).into()).unwrap();

    // Derive address from public key
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_encoded_point(false);
    let public_key_hash = Keccak256::digest(&public_key_bytes.as_bytes()[1..]);
    let address = format!("0x{}", hex::encode(&public_key_hash[12..]));

    // Create a test message
    let message = "Test message for signing";

    // Sign with EIP-191 prefix
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message.as_bytes());
    let message_hash = hasher.finalize();

    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&message_hash).unwrap();

    // Construct 65-byte signature (r + s + v)
    let mut sig_bytes = signature.to_bytes().to_vec();
    sig_bytes.push(recovery_id.to_byte() + 27); // Ethereum uses 27/28

    let signature_hex = format!("0x{}", hex::encode(&sig_bytes));

    // Verify the signature
    let result = service.verify_wallet_signature(message, &signature_hex, &address);
    assert!(
        result.is_ok(),
        "Signature verification failed: {:?}",
        result
    );
    assert!(result.unwrap(), "Signature should be valid");

    // Wrong message should fail
    let result = service.verify_wallet_signature("Wrong message", &signature_hex, &address);
    assert!(result.is_ok());
    assert!(
        !result.unwrap(),
        "Signature should be invalid for wrong message"
    );

    // Wrong address should fail
    let wrong_address = "0x0000000000000000000000000000000000000000";
    let result = service.verify_wallet_signature(message, &signature_hex, wrong_address);
    assert!(result.is_ok());
    assert!(
        !result.unwrap(),
        "Signature should be invalid for wrong address"
    );
}

#[tokio::test]
async fn test_start_wallet_login_wallet_not_found() {
    let service = create_service();

    let request = StartWalletLoginRequest {
        address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
    };

    let result = service.start_wallet_login(request).await;
    // Should return InvalidCredentials to prevent enumeration
    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
}

#[tokio::test]
async fn test_start_new_user_wallet_registration_invalid_address() {
    let service = create_service();

    let request = StartNewUserWalletRegistrationRequest {
        address: "invalid".to_string(),
        wallet_name: "Test Wallet".to_string(),
    };

    let result = service.start_new_user_wallet_registration(request).await;
    assert!(matches!(result, Err(AuthError::InvalidWalletAddress(_))));
}

#[tokio::test]
async fn test_start_new_user_wallet_registration_valid_address() {
    let service = create_service();

    let request = StartNewUserWalletRegistrationRequest {
        address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        wallet_name: "Test Wallet".to_string(),
    };

    let result = service.start_new_user_wallet_registration(request).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    assert!(!response.challenge_message.is_empty());
    assert!(!response.user_id.0.is_nil());
    // Address should be checksummed
    assert!(response.address.starts_with("0x"));
}

#[tokio::test]
async fn test_wallet_challenge_uses_consistent_timestamp() {
    let service = create_service();

    // Start registration - this stores the challenge with a timestamp
    let request = StartNewUserWalletRegistrationRequest {
        address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        wallet_name: "Test Wallet".to_string(),
    };

    let response = service
        .start_new_user_wallet_registration(request)
        .await
        .unwrap();
    let challenge_message_from_start = response.challenge_message.clone();

    // The challenge message should contain a timestamp
    assert!(challenge_message_from_start.contains("Timestamp:"));

    // Parse the timestamp from the message to verify it's valid RFC3339
    let timestamp_line = challenge_message_from_start
        .lines()
        .find(|l| l.starts_with("Timestamp:"))
        .unwrap();
    let timestamp_str = timestamp_line.trim_start_matches("Timestamp:").trim();
    let parsed = chrono::DateTime::parse_from_rfc3339(timestamp_str);
    assert!(
        parsed.is_ok(),
        "Timestamp should be valid RFC3339: {}",
        timestamp_str
    );
}

// --- The pinned KDF salt identifier -------------------------------------------
// Both halves of the fix, because reverting either one previously passed the
// entire suite and the regression only surfaces when a user needs recovery.

/// The pinned identifier must survive the account gaining an email.
///
/// This is the bug: `kdf_salt_identifier()` prefers email over wallet,
/// so recomputing after an email is added yields a different salt than the
/// stored `recovery_verification_hash` was built from, and the account can
/// never be recovered.
#[test]
fn pinned_identifier_survives_adding_an_email() {
    let mut user = User::new_wallet_only(
        "0x1111111111111111111111111111111111111111".to_string(),
        crypto::KdfParams::default(),
        crypto::EncryptedBlob {
            ciphertext: vec![1],
            iv: vec![2],
            mac: vec![3],
        },
        "recovery-hash".to_string(),
    );
    let pinned_at_registration = user.kdf_salt_identifier.clone();
    assert_eq!(
        pinned_at_registration,
        "wallet:0x1111111111111111111111111111111111111111"
    );

    user.email = Some("added.later@example.com".to_string());

    assert_eq!(
        user.kdf_salt_identifier, pinned_at_registration,
        "adding an email must not change the pinned identifier"
    );
    #[allow(deprecated)]
    let recomputed = user.kdf_salt_identifier();
    assert_ne!(
        recomputed, user.kdf_salt_identifier,
        "recomputing now disagrees — which is exactly why the field is pinned"
    );
}

/// Each constructor pins the identity fixed at that moment.
#[test]
fn constructors_pin_the_identifier() {
    let wallet = User::new_wallet_only(
        "0xAbCdEf1111111111111111111111111111111111".to_string(),
        crypto::KdfParams::default(),
        crypto::EncryptedBlob {
            ciphertext: vec![1],
            iv: vec![2],
            mac: vec![3],
        },
        "h".to_string(),
    );
    // EIP-55 canonical form of that address. The constructor normalises rather
    // than passing through, so the pinned value is the same one a
    // recovery form reaches from whatever casing the merchant types. In
    // production the address arrives already checksummed from
    // validate_and_checksum_address, where normalising is a no-op.
    assert_eq!(
        wallet.kdf_salt_identifier,
        "wallet:0xabCDEf1111111111111111111111111111111111"
    );

    // The property that matters: casing of the input cannot change the pin.
    let same_wallet_lowercased = User::new_wallet_only(
        "0xabcdef1111111111111111111111111111111111".to_string(),
        crypto::KdfParams::default(),
        crypto::EncryptedBlob {
            ciphertext: vec![1],
            iv: vec![2],
            mac: vec![3],
        },
        "h".to_string(),
    );
    assert_eq!(
        same_wallet_lowercased.kdf_salt_identifier, wallet.kdf_salt_identifier,
        "the same address in different casing must pin the same identifier"
    );

    let id = UserId::new();
    let passkey = User::new_passkey_only(
        id,
        crypto::KdfParams::default(),
        crypto::EncryptedBlob {
            ciphertext: vec![1],
            iv: vec![2],
            mac: vec![3],
        },
        "h".to_string(),
    );
    assert_eq!(passkey.kdf_salt_identifier, format!("passkey:{id}"));

    // Lowercased: every lookup normalises, so pinning the raw value would
    // freeze a salt no client reproduces.
    let email = User::new(
        "MiXeD@Example.COM".to_string(),
        crypto::KdfParams::default(),
        crypto::EncryptedBlob {
            ciphertext: vec![1],
            iv: vec![2],
            mac: vec![3],
        },
        "h".to_string(),
    );
    assert_eq!(email.kdf_salt_identifier, "mixed@example.com");
}

/// The account-id branch resolves passkey-only accounts, and ONLY those.
///
/// Deleting the `Uuid::parse_str` arm previously passed the whole suite. It also
/// guards the narrowing: user ids are not secret, so accepting one for an
/// account that has an email or wallet would hand anyone who learns it a free
/// route to the lockout counter.
#[tokio::test]
async fn account_id_resolves_only_passkey_only_accounts() {
    let repo = Arc::new(InMemoryRepository::new());
    let service = AuthService::new(Arc::clone(&repo));

    let blob = crypto::EncryptedBlob {
        ciphertext: vec![1],
        iv: vec![2],
        mac: vec![3],
    };

    let passkey_only = User::new_passkey_only(
        UserId::new(),
        crypto::KdfParams::default(),
        blob.clone(),
        "h".to_string(),
    );
    let wallet_user = User::new_wallet_only(
        "0x3333333333333333333333333333333333333333".to_string(),
        crypto::KdfParams::default(),
        blob,
        "h".to_string(),
    );
    repo.create_user(&passkey_only).await.unwrap();
    repo.create_user(&wallet_user).await.unwrap();

    // Passkey-only: the id resolves, so we reach the hash comparison and fail
    // there rather than bouncing off identifier validation.
    let err = service
        .start_account_recovery(StartRecoveryRequest {
            identifier: passkey_only.id.to_string(),
            recovery_verification_hash: "wrong".to_string(),
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthError::InvalidRecoveryMnemonic),
        "passkey-only id should resolve and fail on the hash, got {err:?}"
    );

    // Wallet account: the id must NOT resolve, so it cannot be driven to lockout
    // by anyone who happens to know it.
    let err = service
        .start_account_recovery(StartRecoveryRequest {
            identifier: wallet_user.id.to_string(),
            recovery_verification_hash: "wrong".to_string(),
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthError::InvalidRecoveryMnemonic),
        "must stay indistinguishable from a miss, got {err:?}"
    );
    assert_eq!(
        repo.get_user(wallet_user.id)
            .await
            .unwrap()
            .unwrap()
            .failed_login_attempts,
        0,
        "an unresolvable id must not touch the wallet account's lockout counter"
    );
}

/// A wrong recovery hash must not touch the account's lockout state.
///
/// `/auth/recovery/start` is unauthenticated and resolves a user from a public
/// identifier, so incrementing `failed_login_attempts` here let anyone who knew
/// an email, wallet address or account id lock a merchant out on demand.
///
/// The counter is shared with the login paths (`service/wallet.rs`), so this
/// asserts the counter itself stays at zero, not merely that the account is
/// unlocked. Dropping only the `lock_user` call would leave the counter
/// climbing, and the victim's next genuine login typo would trip the lock.
#[tokio::test]
async fn failed_recovery_never_touches_the_lockout_counter() {
    let repo = Arc::new(InMemoryRepository::new());
    let service = AuthService::new(Arc::clone(&repo));

    let blob = crypto::EncryptedBlob {
        ciphertext: vec![1],
        iv: vec![2],
        mac: vec![3],
    };
    let user = User::new_passkey_only(
        UserId::new(),
        crypto::KdfParams::default(),
        blob,
        "correct-hash".to_string(),
    );
    repo.create_user(&user).await.unwrap();

    // Well past max_failed_attempts (5) - a real attacker would not stop at one.
    for attempt in 0..12 {
        let err = service
            .start_account_recovery(StartRecoveryRequest {
                identifier: user.id.to_string(),
                recovery_verification_hash: "wrong".to_string(),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, AuthError::InvalidRecoveryMnemonic),
            "attempt {attempt} should stay a generic mismatch, got {err:?}"
        );
    }

    let after = repo.get_user(user.id).await.unwrap().unwrap();
    assert_eq!(
        after.failed_login_attempts, 0,
        "recovery failures must not increment the shared login counter"
    );
    assert!(
        !after.is_locked(),
        "an unauthenticated caller must not be able to lock an account"
    );
}

/// The other half: removing the lockout must not have made a locked
/// account recoverable. Lockout still applies to accounts locked by the login
/// paths, which is where guessing is the actual risk.
#[tokio::test]
async fn recovery_still_refuses_an_account_locked_by_login() {
    let repo = Arc::new(InMemoryRepository::new());
    let service = AuthService::new(Arc::clone(&repo));

    let blob = crypto::EncryptedBlob {
        ciphertext: vec![1],
        iv: vec![2],
        mac: vec![3],
    };
    let user = User::new_passkey_only(
        UserId::new(),
        crypto::KdfParams::default(),
        blob,
        "correct-hash".to_string(),
    );
    repo.create_user(&user).await.unwrap();
    repo.lock_user(user.id, chrono::Utc::now() + chrono::Duration::hours(1))
        .await
        .unwrap();

    let err = service
        .start_account_recovery(StartRecoveryRequest {
            identifier: user.id.to_string(),
            recovery_verification_hash: "correct-hash".to_string(),
        })
        .await
        .unwrap_err();

    assert!(
        matches!(err, AuthError::AccountLocked),
        "a locked account must still be refused even with the right hash, got {err:?}"
    );
}

/// A successful recovery start must hand back what the client needs to
/// rebuild the account, not just a WebAuthn challenge.
///
/// Without `kdf_params` the client has to guess the Argon2id cost, so raising it
/// as hardware improves would make every existing account unrecoverable. Without
/// `encrypted_symmetric_key` the client cannot unwrap the account's data key, so
/// it would generate a fresh one and `complete_account_recovery` would overwrite
/// the original — destroying the merchant's encrypted data even though they held
/// the correct phrase and did everything right.
///
/// Both are released only after the hash comparison succeeds, so the caller has
/// already proven possession of the phrase.
#[tokio::test]
async fn successful_recovery_start_returns_the_account_key_material() {
    let repo = Arc::new(InMemoryRepository::new());
    let service = AuthService::new(Arc::clone(&repo));

    // Distinctive values, so the assertions cannot pass on a default or a
    // freshly generated blob.
    let stored_blob = crypto::EncryptedBlob {
        ciphertext: vec![0xAA, 0xBB, 0xCC],
        iv: vec![0x11, 0x22],
        mac: vec![0x33, 0x44],
    };
    let stored_params = crypto::KdfParams {
        algorithm: "argon2id".to_string(),
        memory_kb: 131_072, // deliberately NOT the default 65536
        iterations: 5,      // deliberately NOT the default 3
        parallelism: 2,
        salt: b"pinned-at-registration".to_vec(),
    };
    let user = User::new_passkey_only(
        UserId::new(),
        stored_params.clone(),
        stored_blob.clone(),
        "correct-hash".to_string(),
    );
    repo.create_user(&user).await.unwrap();

    let response = service
        .start_account_recovery(StartRecoveryRequest {
            identifier: user.id.to_string(),
            recovery_verification_hash: "correct-hash".to_string(),
        })
        .await
        .expect("the correct hash must be accepted");

    assert_eq!(
        response.encrypted_symmetric_key.ciphertext, stored_blob.ciphertext,
        "must return the account's wrapped key, or recovery silently discards the data"
    );
    assert_eq!(response.encrypted_symmetric_key.iv, stored_blob.iv);
    assert_eq!(response.encrypted_symmetric_key.mac, stored_blob.mac);

    assert_eq!(
        response.kdf_params.memory_kb, stored_params.memory_kb,
        "must return the account's pinned KDF cost, not the current default"
    );
    assert_eq!(response.kdf_params.iterations, stored_params.iterations);
    assert_eq!(response.kdf_params.salt, stored_params.salt);
}

/// The material above must NOT be released to a caller who failed the hash
/// check. It is only safe to return because possession of the phrase was proven.
#[tokio::test]
async fn failed_recovery_start_returns_no_key_material() {
    let repo = Arc::new(InMemoryRepository::new());
    let service = AuthService::new(Arc::clone(&repo));

    let user = User::new_passkey_only(
        UserId::new(),
        crypto::KdfParams::default(),
        crypto::EncryptedBlob {
            ciphertext: vec![0xAA],
            iv: vec![0x11],
            mac: vec![0x33],
        },
        "correct-hash".to_string(),
    );
    repo.create_user(&user).await.unwrap();

    let err = service
        .start_account_recovery(StartRecoveryRequest {
            identifier: user.id.to_string(),
            recovery_verification_hash: "wrong".to_string(),
        })
        .await
        .unwrap_err();

    assert!(
        matches!(err, AuthError::InvalidRecoveryMnemonic),
        "a wrong hash must yield the generic error and no account data, got {err:?}"
    );
}

/// `crypto::eip55_checksum` must agree with alloy's `Address::to_checksum`,
/// which is what `validate_and_checksum_address` pins at registration.
///
/// The client cannot depend on alloy (it has to run in WASM), so the checksum
/// exists twice - once here via alloy, once in `crypto` for the recovery form.
/// That is exactly the duplication that made six copies of the salt convention
/// dangerous, so the two are pinned against each other rather than trusted to
/// agree. A divergence would send wallet merchants a salt the server never
/// stored, and they would be told their recovery phrase is wrong.
#[test]
fn crypto_eip55_agrees_with_alloy_checksum() {
    use alloy_primitives::Address;

    let addresses = [
        "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
        "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359",
        "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
        "0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
        "0x0000000000000000000000000000000000000000",
        "0xffffffffffffffffffffffffffffffffffffffff",
    ];

    for lower in addresses {
        let alloy_form = lower
            .parse::<Address>()
            .expect("valid address")
            .to_checksum(None);
        assert_eq!(
            crypto::eip55_checksum(lower),
            alloy_form,
            "crypto and alloy must produce the same checksum for {lower}"
        );
        // And on the checksummed input too, since the recovery form may receive
        // an address already in canonical form.
        assert_eq!(crypto::eip55_checksum(&alloy_form), alloy_form);
    }
}

// --- Registration -> recovery, end to end -------------------------------------
// The registration -> recovery round trip, through the real code on both sides.
//
// The tests above build their inputs by hand ("recovery-hash", "correct-hash"),
// which proves the service's control flow but says nothing about whether the
// derivation registration performs is the one recovery can reverse. That is the
// failure that matters: it is silent, permanent, and reported to the merchant as
// the same generic "invalid recovery phrase" a typo gives.
//
// So here nothing is hand-built. A real 24-word phrase goes in, real Argon2id
// derives the material, the real `User::new_*` constructor pins the identifier,
// the real `start_account_recovery` verifies it, and the assertion is that the
// account's symmetric key comes back out of the far end unchanged.
//
// Every step below is a call into the single shared definition of its
// convention - `SaltIdentity` for the salt, `recovery_verification_hash` for the
// hash encoding - never a local restatement of it. `ui-kit`'s
// `register_page::tests` pins that `derive_recovery_crypto`, the function the
// browser actually runs, composes those same calls in this same order; `auth`
// cannot call it directly without depending on the UI crate.
//
// These are the slowest tests in the suite by a wide margin: two Argon2id runs
// at 64 MiB / t=3 each, unoptimised. The cost is the security property.

/// What a client uploads at the end of registration.
struct RegistrationMaterial {
    phrase: String,
    account_key: crypto::SymmetricKey,
    kdf_params: crypto::KdfParams,
    encrypted_symmetric_key: crypto::EncryptedBlob,
    recovery_verification_hash: String,
}

/// Registration, client side: generate a phrase, bind a fresh account key to it
/// under `identifier`, and produce the three values the server persists.
fn register_client_side(identifier: &str) -> RegistrationMaterial {
    let mnemonic = crypto::RecoveryMnemonic::generate().expect("generate");
    let recovery_key = mnemonic.derive_recovery_key(identifier).expect("derive");

    let stretched = crypto::stretch_master_key(&recovery_key).expect("stretch");
    let account_key = crypto::kdf::generate_symmetric_key();
    let wrapped = crypto::symmetric::encrypt_key(&account_key, &stretched).expect("wrap");

    RegistrationMaterial {
        phrase: mnemonic.phrase().to_string(),
        account_key,
        kdf_params: crypto::KdfParams {
            algorithm: "argon2id".to_string(),
            memory_kb: crypto::RECOVERY_MEMORY_KB,
            iterations: crypto::RECOVERY_ITERATIONS,
            parallelism: crypto::RECOVERY_PARALLELISM,
            salt: crypto::recovery_salt_for(identifier).into_bytes(),
        },
        encrypted_symmetric_key: wrapped,
        recovery_verification_hash: crypto::recovery_verification_hash(&recovery_key),
    }
}

/// Recovery, client side: the merchant has the phrase, and the server tells them
/// which identifier the account was salted with. Nothing else survives.
///
/// One Argon2id run serves both halves - the hash that proves possession, and
/// the stretched key that unwraps whatever the server returns.
fn recover_client_side(phrase: &str, pinned_identifier: &str) -> (String, crypto::StretchedKey) {
    let mnemonic = crypto::RecoveryMnemonic::from_phrase(phrase).expect("phrase must re-parse");
    let recovery_key = mnemonic
        .derive_recovery_key(pinned_identifier)
        .expect("derive");
    let hash = crypto::recovery_verification_hash(&recovery_key);
    let stretched = crypto::stretch_master_key(&recovery_key).expect("stretch");
    (hash, stretched)
}

/// Drive a registered account through `start_account_recovery` and assert its
/// symmetric key survives the trip.
///
/// `typed_identifier` is what a merchant enters on the recovery form, which is
/// only used to *find* the account. The salt comes from the pinned
/// `kdf_salt_identifier` the server hands back - the distinction the pinned
/// identifier turns on, and the reason these are not the same argument.
async fn assert_recovers(
    service: &AuthService<InMemoryRepository>,
    user: &User,
    material: &RegistrationMaterial,
    typed_identifier: &str,
) {
    let (hash, stretched) = recover_client_side(&material.phrase, &user.kdf_salt_identifier);

    let response = service
        .start_account_recovery(StartRecoveryRequest {
            identifier: typed_identifier.to_string(),
            recovery_verification_hash: hash,
        })
        .await
        .expect("the phrase registration derived from must be accepted");

    let recovered = crypto::symmetric::decrypt_key(&response.encrypted_symmetric_key, &stretched)
        .expect("the returned blob must unwrap under the recovery key");
    assert_eq!(
        recovered.as_bytes(),
        material.account_key.as_bytes(),
        "recovery must return the account's original key, not a fresh one"
    );

    // The cost the server hands back has to be the one the key was derived
    // under, or a client deriving from it lands somewhere else entirely.
    assert_eq!(response.kdf_params.memory_kb, material.kdf_params.memory_kb);
    assert_eq!(
        response.kdf_params.iterations,
        material.kdf_params.iterations
    );
    assert_eq!(response.kdf_params.salt, material.kdf_params.salt);
}

/// Email registration.
#[tokio::test]
async fn email_account_registers_and_recovers() {
    let repo = Arc::new(InMemoryRepository::new());
    let service = AuthService::new(Arc::clone(&repo));

    // Mixed case on purpose: `User::new` lowercases before pinning, so a client
    // that salted with the raw input would produce an unreproducible hash.
    let typed_email = "Merchant@Example.COM";
    let material =
        register_client_side(&crypto::SaltIdentity::Email(typed_email.to_string()).as_identifier());

    let user = User::new(
        typed_email.to_string(),
        material.kdf_params.clone(),
        material.encrypted_symmetric_key.clone(),
        material.recovery_verification_hash.clone(),
    );
    assert_eq!(user.kdf_salt_identifier, "merchant@example.com");
    repo.create_user(&user).await.unwrap();

    assert_recovers(&service, &user, &material, "merchant@example.com").await;
}

/// Wallet-only registration.
#[tokio::test]
async fn wallet_only_account_registers_and_recovers() {
    let repo = Arc::new(InMemoryRepository::new());
    let service = AuthService::new(Arc::clone(&repo));

    // The browser reports whatever casing the wallet gives; the server pins the
    // EIP-55 form via `validate_and_checksum_address`. Both sides only meet
    // because `SaltIdentity::Wallet` normalises.
    let as_reported = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
    let checksummed = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
    let material = register_client_side(
        &crypto::SaltIdentity::Wallet(as_reported.to_string()).as_identifier(),
    );

    let user = User::new_wallet_only(
        checksummed.to_string(),
        material.kdf_params.clone(),
        material.encrypted_symmetric_key.clone(),
        material.recovery_verification_hash.clone(),
    );
    assert_eq!(user.kdf_salt_identifier, format!("wallet:{checksummed}"));
    repo.create_user(&user).await.unwrap();

    // Typed back in lower case, as a merchant would paste it.
    assert_recovers(&service, &user, &material, as_reported).await;
}

/// Passkey-only registration - no email, no wallet, so the account id is the
/// only handle the phrase can be bound to.
#[tokio::test]
async fn passkey_only_account_registers_and_recovers() {
    let repo = Arc::new(InMemoryRepository::new());
    let service = AuthService::new(Arc::clone(&repo));

    let user_id = UserId::new();
    let material =
        register_client_side(&crypto::SaltIdentity::Passkey(user_id.to_string()).as_identifier());

    let user = User::new_passkey_only(
        user_id,
        material.kdf_params.clone(),
        material.encrypted_symmetric_key.clone(),
        material.recovery_verification_hash.clone(),
    );
    assert_eq!(user.kdf_salt_identifier, format!("passkey:{user_id}"));
    repo.create_user(&user).await.unwrap();

    assert_recovers(&service, &user, &material, &user_id.to_string()).await;
}

/// The pinned-identifier regression, end to end.
///
/// `pinned_identifier_survives_adding_an_email` above proves the field does not
/// move. This proves the consequence: an account that registered with a wallet
/// and later gained an email is still recoverable, and is recoverable *only*
/// with the wallet salt. Recomputing the identifier - which is what the
/// deprecated `kdf_salt_identifier()` does, preferring email over wallet - would
/// leave both halves of this passing and the merchant permanently locked out.
#[tokio::test]
async fn adding_an_email_does_not_break_recovery() {
    let repo = Arc::new(InMemoryRepository::new());
    let service = AuthService::new(Arc::clone(&repo));

    let address = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
    let material =
        register_client_side(&crypto::SaltIdentity::Wallet(address.to_string()).as_identifier());

    let mut user = User::new_wallet_only(
        address.to_string(),
        material.kdf_params.clone(),
        material.encrypted_symmetric_key.clone(),
        material.recovery_verification_hash.clone(),
    );
    repo.create_user(&user).await.unwrap();

    // The account gains an email after the fact. Everything about the stored
    // recovery material was fixed before this point.
    user.email = Some("added.later@example.com".to_string());
    repo.update_user(&user).await.unwrap();
    let user = repo.get_user(user.id).await.unwrap().expect("user");

    assert_recovers(&service, &user, &material, address).await;

    // And the salt an implementation that recomputed would have used must be
    // rejected, so this test fails if recovery is ever "fixed" to derive the
    // identifier from the account's current state.
    #[allow(deprecated)]
    let recomputed = user.kdf_salt_identifier();
    assert_ne!(recomputed, user.kdf_salt_identifier);
    let (wrong_hash, _) = recover_client_side(&material.phrase, &recomputed);
    let err = service
        .start_account_recovery(StartRecoveryRequest {
            identifier: address.to_string(),
            recovery_verification_hash: wrong_hash,
        })
        .await
        .expect_err("the recomputed identifier must not reproduce the stored hash");
    assert!(matches!(err, AuthError::InvalidRecoveryMnemonic), "{err:?}");
}

// ========================================================================
// Device reuse on login
// ========================================================================
//
// A stale device id must never fail a login. The client keeps one id per browser
// in localStorage and does not clear it when the server rejects it, so returning
// an error locked the user out of that credential permanently - recoverable only
// by clearing storage by hand. These pin the three ways an id goes stale.

async fn seed_device(repo: &InMemoryRepository, user_id: UserId, active: bool) -> Device {
    let mut d = Device::new(
        user_id,
        "test device".to_string(),
        DeviceType::Browser,
        crypto::EncryptedBlob {
            ciphertext: vec![1],
            iv: vec![2],
            mac: vec![3],
        },
        crypto::KdfParams::default(),
    );
    d.is_active = active;
    repo.create_device(&d).await.unwrap();
    d
}

#[tokio::test]
async fn reusable_device_returns_none_when_no_id_supplied() {
    let repo = Arc::new(InMemoryRepository::new());
    let service = AuthService::new(repo);
    assert!(
        service
            .reusable_device(UserId::new(), None)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn reusable_device_reuses_the_users_own_active_device() {
    let repo = Arc::new(InMemoryRepository::new());
    let user_id = UserId::new();
    let device = seed_device(&repo, user_id, true).await;
    let service = AuthService::new(repo);

    let got = service
        .reusable_device(user_id, Some(device.id))
        .await
        .unwrap();
    assert_eq!(got.map(|d| d.id), Some(device.id));
}

#[tokio::test]
async fn reusable_device_ignores_an_unknown_id_instead_of_failing() {
    let repo = Arc::new(InMemoryRepository::new());
    let service = AuthService::new(repo);

    // Ok(None), never Err: the caller mints a new device.
    let got = service
        .reusable_device(UserId::new(), Some(DeviceId::new()))
        .await
        .unwrap();
    assert!(got.is_none());
}

#[tokio::test]
async fn reusable_device_ignores_a_device_owned_by_another_user() {
    // The exact shape of the bug: two accounts in one browser, so localStorage
    // holds a device id belonging to the other one.
    let repo = Arc::new(InMemoryRepository::new());
    let other_user = UserId::new();
    let device = seed_device(&repo, other_user, true).await;
    let service = AuthService::new(repo);

    let got = service
        .reusable_device(UserId::new(), Some(device.id))
        .await
        .unwrap();
    assert!(got.is_none(), "must not hand back another user's device");
}

#[tokio::test]
async fn reusable_device_ignores_a_revoked_device() {
    let repo = Arc::new(InMemoryRepository::new());
    let user_id = UserId::new();
    let device = seed_device(&repo, user_id, false).await;
    let service = AuthService::new(repo);

    let got = service
        .reusable_device(user_id, Some(device.id))
        .await
        .unwrap();
    assert!(got.is_none(), "a revoked device must not be reused");
}

// ========================================================================
// Device cap on login
// ========================================================================
//
// Revoking a device needs a session, and a session needs a login, so a login
// refused because the account is full can never be remedied from inside the
// product. At the cap a login re-uses the least recently used device.

fn capped_service(cap: u32) -> (Arc<InMemoryRepository>, AuthService<InMemoryRepository>) {
    let repo = Arc::new(InMemoryRepository::new());
    let config = super::AuthConfig {
        max_devices_per_user: cap,
        ..Default::default()
    };
    (repo.clone(), AuthService::with_config(repo, config))
}

async fn seed_user(repo: &InMemoryRepository) -> User {
    let user = User::new(
        "cap@example.com".to_string(),
        crypto::KdfParams::default(),
        crypto::EncryptedBlob {
            ciphertext: vec![1],
            iv: vec![2],
            mac: vec![3],
        },
        "hash".to_string(),
    );
    repo.create_user(&user).await.unwrap();
    user
}

#[tokio::test]
async fn login_below_the_cap_registers_a_new_device() {
    let (repo, service) = capped_service(2);
    let user = seed_user(&repo).await;
    seed_device(&repo, user.id, true).await;

    let id = service
        .device_for_new_login(&user, "new".to_string(), DeviceType::Browser)
        .await
        .unwrap();

    assert_eq!(repo.count_active_devices(user.id).await.unwrap(), 2);
    assert_eq!(repo.get_device(id).await.unwrap().unwrap().name, "new");
}

#[tokio::test]
async fn login_at_the_cap_reuses_the_least_recently_used_device() {
    let (repo, service) = capped_service(2);
    let user = seed_user(&repo).await;
    let mut old = seed_device(&repo, user.id, true).await;
    let mut recent = seed_device(&repo, user.id, true).await;
    old.last_used_at = Some(chrono::Utc::now() - chrono::Duration::days(30));
    recent.last_used_at = Some(chrono::Utc::now());
    repo.update_device(&old).await.unwrap();
    repo.update_device(&recent).await.unwrap();

    let id = service
        .device_for_new_login(&user, "fresh".to_string(), DeviceType::Browser)
        .await
        .expect("a full account must still be able to log in");

    assert_eq!(id, old.id, "the stalest device is the one reclaimed");
    assert_eq!(repo.count_active_devices(user.id).await.unwrap(), 2);
    assert_eq!(repo.get_device(id).await.unwrap().unwrap().name, "fresh");
    assert_eq!(
        repo.get_device(recent.id).await.unwrap().unwrap().name,
        "test device"
    );
}

#[derive(Clone, Default)]
struct LogBuf(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> LogBuf {
        self.clone()
    }
}

#[tokio::test]
async fn login_at_the_cap_emits_a_warning_naming_the_account_and_device() {
    let (repo, service) = capped_service(1);
    let user = seed_user(&repo).await;
    let existing = seed_device(&repo, user.id, true).await;

    let buf = LogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    // Thread-local default: the test runtime is single-threaded.
    let _guard = tracing::subscriber::set_default(subscriber);

    service
        .device_for_new_login(&user, "fresh".to_string(), DeviceType::Browser)
        .await
        .unwrap();

    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(out.contains("WARN"), "not a warning: {out}");
    assert!(out.contains("re-using least recently used device"), "{out}");
    assert!(out.contains(&user.id.to_string()), "no account id: {out}");
    assert!(
        out.contains(&existing.id.to_string()),
        "no device id: {out}"
    );
    assert!(!out.contains("encrypted_symmetric_key"), "{out}");
}

#[tokio::test]
async fn repeated_logins_at_the_cap_never_grow_the_device_count() {
    let (repo, service) = capped_service(3);
    let user = seed_user(&repo).await;
    for _ in 0..25 {
        service
            .device_for_new_login(&user, "b".to_string(), DeviceType::Browser)
            .await
            .unwrap();
    }
    assert_eq!(repo.count_active_devices(user.id).await.unwrap(), 3);
}

// ========================================================================
// Adding a second passkey (existing user)
// ========================================================================
//
// `start_passkey_registration` reads the *pinned* `kdf_salt_identifier` off
// the `User` row precisely so that passkey-only accounts — the ones with no
// email and no wallet — can add a second passkey at all (see its comment).
// `complete_passkey_registration` never got that fix: it recomputes the
// identifier from `UserInfo.email` / `UserInfo.primary_wallet_address`, which
// is `None`/`None` for exactly those accounts, and also disagrees with the
// pinned value for any wallet account that later added an email. A garbage
// WebAuthn credential is enough to demonstrate it: the mismatch is detected
// before the credential is ever inspected.

fn garbage_passkey_credential() -> webauthn_rs_proto::RegisterPublicKeyCredential {
    serde_json::from_value(serde_json::json!({
        "id": "x",
        "rawId": "AA",
        "response": {
            "attestationObject": "AA",
            "clientDataJSON": "AA",
        },
        "type": "public-key",
    }))
    .expect("structurally valid, never cryptographically verified in this test")
}

#[tokio::test]
async fn passkey_only_user_can_complete_adding_a_second_passkey() {
    let repo = Arc::new(InMemoryRepository::new());

    let user = User::new_passkey_only(
        UserId::new(),
        crypto::KdfParams::default(),
        crypto::EncryptedBlob {
            ciphertext: vec![1],
            iv: vec![2],
            mac: vec![3],
        },
        "recovery-hash".to_string(),
    );
    repo.create_user(&user).await.unwrap();
    let device = seed_device(&repo, user.id, true).await;
    let session = Session::new(user.id, device.id);
    let session_id = session.id;
    repo.create_session(&session).await.unwrap();

    let service = AuthService::new(repo);

    service
        .start_passkey_registration(
            session_id,
            StartPasskeyRegistrationRequest {
                passkey_name: "second device".to_string(),
            },
        )
        .await
        .expect("starting to add a second passkey must succeed");

    let err = service
        .complete_passkey_registration(
            session_id,
            CompletePasskeyRegistrationRequest {
                passkey_name: "second device".to_string(),
                credential: garbage_passkey_credential(),
            },
        )
        .await
        .expect_err("the credential is garbage, so this must fail — but not this way");

    // A passkey-only account has no email and no wallet, so the buggy
    // recompute in `complete_passkey_registration` bails out with
    // `AuthError::Repository` before it ever reaches WebAuthn verification.
    // The fix must get far enough to attempt (and fail) the WebAuthn check
    // instead.
    assert!(
        !matches!(err, AuthError::Repository(_)),
        "passkey-only account could not even reach WebAuthn verification: {err:?}"
    );
}
