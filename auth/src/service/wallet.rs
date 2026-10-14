//! Ethereum wallet authentication methods.

use alloy_primitives::Address;
use chrono::Utc;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::Digest;
use sha3::Keccak256;

use crate::error::{AuthError, Result};
#[cfg(feature = "metrics")]
use crate::metrics;
use crate::models::{
    CompleteNewUserWalletRegistrationRequest, CompleteWalletLoginRequest,
    CompleteWalletRegistrationRequest, Device, LoginResponse, Session, SessionId,
    StartNewUserWalletRegistrationRequest, StartNewUserWalletRegistrationResponse,
    StartWalletLoginRequest, StartWalletLoginResponse, StartWalletRegistrationRequest,
    StartWalletRegistrationResponse, User, UserId, WalletChallenge, WalletCredential,
    WalletCredentialId, WalletInfo,
};
use crate::repository::{
    ChallengeRepository, DeviceRepository, PasskeyRepository, SessionRepository, UserRepository,
    WalletRepository,
};

use super::WebAuthnAuthService;

// =============================================================================
// Wallet Crypto Helpers
// =============================================================================

impl<R> WebAuthnAuthService<R>
where
    R: UserRepository
        + DeviceRepository
        + SessionRepository
        + PasskeyRepository
        + WalletRepository
        + ChallengeRepository,
{
    /// Validate and checksum an Ethereum address (EIP-55).
    ///
    /// Returns the checksummed address string or an error if invalid.
    pub(super) fn validate_and_checksum_address(&self, address: &str) -> Result<String> {
        // Parse the address - this validates length and hex format
        let addr: Address = address
            .parse()
            .map_err(|_| AuthError::InvalidWalletAddress(address.to_string()))?;

        // Return the checksummed representation
        Ok(addr.to_checksum(None))
    }

    /// Generate a random challenge for wallet authentication.
    pub(super) fn generate_wallet_challenge(&self) -> String {
        // Use two UUIDs to get 32 bytes of randomness
        let uuid1 = uuid::Uuid::new_v4();
        let uuid2 = uuid::Uuid::new_v4();
        format!("{}{}", uuid1.as_simple(), uuid2.as_simple())
    }

    /// Generate the challenge message for wallet signing (EIP-191 personal_sign format).
    ///
    /// The timestamp parameter ensures the same message is generated during both
    /// challenge creation and verification.
    pub(super) fn generate_wallet_challenge_message(
        &self,
        challenge: &str,
        address: &str,
        timestamp: &chrono::DateTime<Utc>,
    ) -> String {
        format!(
            "Sign this message to authenticate to {}:\n\nChallenge: {}\nTimestamp: {}\nAddress: {}",
            self.config.rp_name,
            challenge,
            timestamp.to_rfc3339(),
            address
        )
    }

    /// Verify a wallet challenge: check expiry, address match, and signature.
    /// Returns the challenge message on success.
    pub(super) async fn verify_wallet_challenge(
        &self,
        user_id: UserId,
        address: &str,
        signature: &str,
    ) -> Result<()> {
        let wallet_challenge = self
            .repo
            .take_wallet_challenge(user_id)
            .await?
            .ok_or(AuthError::WalletChallengeExpired)?;

        // Check expiry
        if Utc::now() - wallet_challenge.created_at > self.config.wallet_challenge_duration {
            return Err(AuthError::WalletChallengeExpired);
        }

        // Verify address matches
        if wallet_challenge.address != address {
            return Err(AuthError::WalletSignatureVerificationFailed);
        }

        // Verify signature using the original timestamp from challenge creation
        let challenge_message = self.generate_wallet_challenge_message(
            &wallet_challenge.challenge,
            address,
            &wallet_challenge.created_at,
        );
        if !self.verify_wallet_signature(&challenge_message, signature, address)? {
            return Err(AuthError::WalletSignatureVerificationFailed);
        }

        Ok(())
    }

    /// Verify an EIP-191 personal_sign signature.
    pub(super) fn verify_wallet_signature(
        &self,
        message: &str,
        signature_hex: &str,
        expected_address: &str,
    ) -> Result<bool> {
        // Parse the signature (65 bytes: r[32] + s[32] + v[1])
        let signature_bytes = hex::decode(signature_hex.trim_start_matches("0x"))
            .map_err(|_| AuthError::WalletSignatureVerificationFailed)?;

        if signature_bytes.len() != 65 {
            return Err(AuthError::WalletSignatureVerificationFailed);
        }

        // Split into r, s, and v
        let r_s = &signature_bytes[0..64];
        let v = signature_bytes[64];

        // Parse the signature
        let signature =
            Signature::from_slice(r_s).map_err(|_| AuthError::WalletSignatureVerificationFailed)?;

        // Determine recovery ID (v is either 27/28 or 0/1)
        let recovery_id = match v {
            27 | 0 => RecoveryId::try_from(0u8),
            28 | 1 => RecoveryId::try_from(1u8),
            _ => return Err(AuthError::WalletSignatureVerificationFailed),
        };

        let recovery_id = recovery_id.map_err(|_| AuthError::WalletSignatureVerificationFailed)?;

        // Hash the message with EIP-191 prefix
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut hasher = Keccak256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(message.as_bytes());
        let message_hash = hasher.finalize();

        // Recover the public key
        let recovered_key =
            VerifyingKey::recover_from_prehash(&message_hash, &signature, recovery_id)
                .map_err(|_| AuthError::WalletSignatureVerificationFailed)?;

        // Convert public key to address
        let public_key_bytes = recovered_key.to_encoded_point(false);
        let public_key_hash = Keccak256::digest(&public_key_bytes.as_bytes()[1..]); // Skip the 0x04 prefix
        let recovered_address = format!("0x{}", hex::encode(&public_key_hash[12..]));

        // Compare addresses (case-insensitive)
        Ok(recovered_address.to_lowercase() == expected_address.to_lowercase())
    }
}

// =============================================================================
// Wallet Login
// =============================================================================

impl<R> WebAuthnAuthService<R>
where
    R: UserRepository
        + DeviceRepository
        + SessionRepository
        + PasskeyRepository
        + WalletRepository
        + ChallengeRepository,
{
    /// Start wallet login for an existing user.
    ///
    /// Verifies the wallet is registered and returns a challenge for signing.
    pub async fn start_wallet_login(
        &self,
        request: StartWalletLoginRequest,
    ) -> Result<StartWalletLoginResponse> {
        // Validate and checksum the address
        let checksummed_address = self.validate_and_checksum_address(&request.address)?;

        // Find the wallet credential
        let wallet = self
            .repo
            .get_wallet_by_address(&checksummed_address)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        // Get the user
        let user = self
            .repo
            .get_user(wallet.user_id)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        // Check if account is locked
        if user.is_locked() {
            #[cfg(feature = "metrics")]
            metrics::record_login_failure();
            return Err(AuthError::AccountLocked);
        }

        // Generate and store challenge state
        let challenge = self.generate_wallet_challenge();
        let wallet_challenge = WalletChallenge::new(challenge, checksummed_address.clone());
        let challenge_message = self.generate_wallet_challenge_message(
            &wallet_challenge.challenge,
            &checksummed_address,
            &wallet_challenge.created_at,
        );
        self.repo
            .store_wallet_challenge(user.id, wallet_challenge)
            .await?;

        Ok(StartWalletLoginResponse {
            challenge_message,
            user_id: user.id,
        })
    }

    /// Complete wallet login.
    pub async fn complete_wallet_login(
        &self,
        request: CompleteWalletLoginRequest,
    ) -> Result<LoginResponse> {
        let checksummed_address = self.validate_and_checksum_address(&request.address)?;

        let user = self
            .repo
            .get_user(request.user_id)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        if user.is_locked() {
            #[cfg(feature = "metrics")]
            metrics::record_login_failure();
            return Err(AuthError::AccountLocked);
        }

        // Verify challenge and signature (with rate limiting on failure)
        if let Err(e) = self
            .verify_wallet_challenge(user.id, &checksummed_address, &request.signature)
            .await
        {
            if matches!(e, AuthError::WalletSignatureVerificationFailed) {
                #[cfg(feature = "metrics")]
                metrics::record_login_failure();
                let attempts = self.repo.increment_failed_logins(user.id).await?;
                if attempts >= self.config.max_failed_attempts {
                    let lock_until = Utc::now() + self.config.lockout_duration;
                    self.repo.lock_user(user.id, lock_until).await?;
                }
            }
            return Err(e);
        }

        self.repo.reset_failed_logins(user.id).await?;

        // Update wallet last_used_at
        let mut wallet = self
            .repo
            .get_wallet_by_address(&checksummed_address)
            .await?
            .ok_or(AuthError::WalletNotFound(checksummed_address.clone()))?;
        wallet.last_used_at = Some(Utc::now());
        self.repo.update_wallet(&wallet).await?;

        // Reuse the client's device if it is usable, otherwise mint a new one.
        // Same reasoning as the passkey path: the signature has already
        // been verified, so a device id that no longer applies is a stale hint,
        // not a login failure. Returning an error here locked a user out of their
        // wallet login until they cleared localStorage by hand.
        let reusable = self.reusable_device(user.id, request.device_id).await?;

        let device_id = if let Some(device) = reusable {
            let mut device = device;
            device.last_used_at = Some(Utc::now());
            let id = device.id;
            self.repo.update_device(&device).await?;
            id
        } else {
            // AT THE CAP, ATTACH TO THE LEAST RECENTLY USED DEVICE RATHER THAN REFUSE.
            //
            // The cap exists to bound stored credentials. Refusing here made it bound
            // LOGINS, and permanently: freeing a slot needs a session, and getting a
            // session needs a free slot. See least_recently_used_device.
            //
            // NOT SILENT. The cap being reached is information - if an eleventh device
            // ever means something is wrong, that signal must survive this fix - so it
            // is logged at warn, naming what the shared record now costs.
            let device_count = self.repo.count_active_devices(user.id).await?;
            if device_count >= self.config.max_devices_per_user {
                match self.least_recently_used_device(user.id).await? {
                    Some(mut lru) => {
                        tracing::warn!(
                            user_id = %user.id,
                            device_id = %lru.id,
                            cap = self.config.max_devices_per_user,
                            "device cap reached; attaching this login to the least recently used \
                             device instead of refusing it. That record now covers more than one \
                             machine: its last-used time is the later of them, and revoking it \
                             signs out all of them. Nothing was signed out here."
                        );
                        lru.last_used_at = Some(Utc::now());
                        let id = lru.id;
                        self.repo.update_device(&lru).await?;
                        id
                    }
                    // No active device to attach to. At a cap of zero this is the honest
                    // answer rather than a contradiction: zero devices are permitted, so
                    // no login is.
                    None => {
                        return Err(AuthError::MaxDevicesReached(
                            self.config.max_devices_per_user,
                        ));
                    }
                }
            } else {
                // Create new device
                let device = Device::new(
                    user.id,
                    request.device_name,
                    request.device_type,
                    user.encrypted_symmetric_key.clone(),
                    user.kdf_params.clone(),
                );
                let new_device_id = device.id;
                self.repo.create_device(&device).await?;
                new_device_id
            }
        };

        // Update last login
        let mut updated_user = user.clone();
        updated_user.last_login_at = Some(Utc::now());
        self.repo.update_user(&updated_user).await?;

        // Create session
        let expires_at = Utc::now() + self.config.session_duration;
        let session = Session::with_expiration(user.id, device_id, expires_at);
        let session_id = session.id;
        self.repo.create_session(&session).await?;

        #[cfg(feature = "metrics")]
        metrics::record_user_login();

        Ok(LoginResponse {
            session_id,
            device_id,
            encrypted_symmetric_key: user.encrypted_symmetric_key,
            kdf_params: user.kdf_params,
            email: user.email,
            primary_wallet_address: user.primary_wallet_address,
            expires_at,
        })
    }
}

// =============================================================================
// New User Wallet Registration
// =============================================================================

impl<R> WebAuthnAuthService<R>
where
    R: UserRepository
        + DeviceRepository
        + SessionRepository
        + PasskeyRepository
        + WalletRepository
        + ChallengeRepository,
{
    /// Start new user registration with wallet (wallet-only account).
    pub async fn start_new_user_wallet_registration(
        &self,
        request: StartNewUserWalletRegistrationRequest,
    ) -> Result<StartNewUserWalletRegistrationResponse> {
        // Validate and checksum the address
        let checksummed_address = self.validate_and_checksum_address(&request.address)?;

        // Check if wallet is already registered
        if self
            .repo
            .get_wallet_by_address(&checksummed_address)
            .await?
            .is_some()
        {
            return Err(AuthError::WalletAlreadyRegistered);
        }

        // Check if wallet is already a primary address for a user
        if self
            .repo
            .get_user_by_wallet_address(&checksummed_address)
            .await?
            .is_some()
        {
            return Err(AuthError::WalletAlreadyRegistered);
        }

        // Generate temporary user ID
        let user_id = UserId::new();

        // Generate and store challenge state
        let challenge = self.generate_wallet_challenge();
        let wallet_challenge = WalletChallenge::new(challenge, checksummed_address.clone());
        let challenge_message = self.generate_wallet_challenge_message(
            &wallet_challenge.challenge,
            &checksummed_address,
            &wallet_challenge.created_at,
        );
        self.repo
            .store_wallet_challenge(user_id, wallet_challenge)
            .await?;

        Ok(StartNewUserWalletRegistrationResponse {
            challenge_message,
            user_id,
            address: checksummed_address,
        })
    }

    /// Complete new user registration with wallet.
    pub async fn complete_new_user_wallet_registration(
        &self,
        request: CompleteNewUserWalletRegistrationRequest,
    ) -> Result<LoginResponse> {
        // Validate address
        let checksummed_address = self.validate_and_checksum_address(&request.address)?;

        // Check if wallet is already registered (race condition check)
        if self
            .repo
            .get_wallet_by_address(&checksummed_address)
            .await?
            .is_some()
        {
            return Err(AuthError::WalletAlreadyRegistered);
        }

        // Verify challenge and signature
        self.verify_wallet_challenge(request.user_id, &checksummed_address, &request.signature)
            .await?;

        // Create the user (wallet-only account)
        let user = User::new_wallet_only(
            checksummed_address.clone(),
            request.kdf_params.clone(),
            request.encrypted_symmetric_key.clone(),
            request.recovery_verification_hash.clone(),
        );
        // Override the auto-generated ID with the one from the challenge
        let mut user = user;
        user.id = request.user_id;
        self.repo.create_user(&user).await?;

        // Create the wallet credential (primary wallet)
        let wallet = WalletCredential::new(
            user.id,
            checksummed_address.clone(),
            request.wallet_name.clone(),
            true, // is_primary
        );
        self.repo.create_wallet(&wallet).await?;

        // Create device
        let device = Device::new(
            user.id,
            request.device_name.clone(),
            request.device_type,
            request.encrypted_symmetric_key.clone(),
            request.kdf_params.clone(),
        );
        let device_id = device.id;
        self.repo.create_device(&device).await?;

        // Create session
        let expires_at = Utc::now() + self.config.session_duration;
        let session = Session::with_expiration(user.id, device_id, expires_at);
        let session_id = session.id;
        self.repo.create_session(&session).await?;

        #[cfg(feature = "metrics")]
        metrics::record_user_registration();

        Ok(LoginResponse {
            session_id,
            device_id,
            encrypted_symmetric_key: request.encrypted_symmetric_key.clone(),
            kdf_params: request.kdf_params.clone(),
            email: None, // Wallet-only account
            primary_wallet_address: Some(checksummed_address),
            expires_at,
        })
    }
}

// =============================================================================
// Wallet Management (Existing User)
// =============================================================================

impl<R> WebAuthnAuthService<R>
where
    R: UserRepository
        + DeviceRepository
        + SessionRepository
        + PasskeyRepository
        + WalletRepository
        + ChallengeRepository,
{
    /// Start adding a wallet to an existing account.
    ///
    /// Requires an active session.
    pub async fn start_wallet_registration(
        &self,
        session_id: SessionId,
        request: StartWalletRegistrationRequest,
    ) -> Result<StartWalletRegistrationResponse> {
        // Validate session
        let (user_info, _session) = self.validate_session(session_id).await?;

        // Validate and checksum the address
        let checksummed_address = self.validate_and_checksum_address(&request.address)?;

        // Check wallet limit
        let wallet_count = self.repo.count_active_wallets(user_info.id).await?;
        if wallet_count >= self.config.max_wallets_per_user {
            return Err(AuthError::MaxWalletsReached(
                self.config.max_wallets_per_user,
            ));
        }

        // Check if wallet is already registered
        if self
            .repo
            .get_wallet_by_address(&checksummed_address)
            .await?
            .is_some()
        {
            return Err(AuthError::WalletAlreadyRegistered);
        }

        // Generate and store challenge state
        let challenge = self.generate_wallet_challenge();
        let wallet_challenge = WalletChallenge::new(challenge, checksummed_address.clone());
        let challenge_message = self.generate_wallet_challenge_message(
            &wallet_challenge.challenge,
            &checksummed_address,
            &wallet_challenge.created_at,
        );
        self.repo
            .store_wallet_challenge(user_info.id, wallet_challenge)
            .await?;

        Ok(StartWalletRegistrationResponse {
            challenge_message,
            address: checksummed_address,
        })
    }

    /// Complete adding a wallet to an existing account.
    pub async fn complete_wallet_registration(
        &self,
        session_id: SessionId,
        request: CompleteWalletRegistrationRequest,
    ) -> Result<WalletInfo> {
        // Validate session
        let (user_info, _session) = self.validate_session(session_id).await?;

        // Validate address
        let checksummed_address = self.validate_and_checksum_address(&request.address)?;

        // Re-check wallet limit (race condition protection)
        let wallet_count = self.repo.count_active_wallets(user_info.id).await?;
        if wallet_count >= self.config.max_wallets_per_user {
            return Err(AuthError::MaxWalletsReached(
                self.config.max_wallets_per_user,
            ));
        }

        // Verify challenge and signature
        self.verify_wallet_challenge(user_info.id, &checksummed_address, &request.signature)
            .await?;

        // Create the wallet credential (not primary for existing users)
        let wallet = WalletCredential::new(
            user_info.id,
            checksummed_address,
            request.wallet_name,
            false, // is_primary = false for additional wallets
        );
        let wallet_info = WalletInfo::from(&wallet);
        self.repo.create_wallet(&wallet).await?;

        Ok(wallet_info)
    }

    /// Get all wallets for the current user.
    ///
    /// Requires a valid session.
    pub async fn get_wallets(&self, session_id: SessionId) -> Result<Vec<WalletInfo>> {
        let (user_info, _session) = self.validate_session(session_id).await?;

        let wallets = self.repo.get_wallets_for_user(user_info.id).await?;

        Ok(wallets
            .iter()
            .filter(|w| w.is_active)
            .map(WalletInfo::from)
            .collect())
    }

    /// Revoke (deactivate) a wallet.
    ///
    /// Cannot revoke the primary wallet if it's the only identifier for the account.
    pub async fn revoke_wallet(
        &self,
        session_id: SessionId,
        wallet_id: WalletCredentialId,
    ) -> Result<()> {
        // Validate session
        let (user_info, _session) = self.validate_session(session_id).await?;

        // Get the wallet
        let wallet = self
            .repo
            .get_wallet(wallet_id)
            .await?
            .ok_or(AuthError::WalletNotFound(wallet_id.to_string()))?;

        // Verify ownership
        if wallet.user_id != user_info.id {
            return Err(AuthError::WalletNotFound(wallet_id.to_string()));
        }

        // Check if this is the primary wallet and user has no email
        if wallet.is_primary && user_info.email.is_none() {
            // Cannot remove the primary wallet if it's the only identifier
            return Err(AuthError::CannotRemovePrimaryWallet);
        }

        // Deactivate the wallet
        self.repo.deactivate_wallet(wallet_id).await
    }
}
