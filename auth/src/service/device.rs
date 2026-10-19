//! Device management methods.

use crate::error::{AuthError, Result};
use crate::models::{Device, DeviceId, DeviceInfo, DeviceType, SessionId, UserId};
use crate::repository::{
    ChallengeRepository, DeviceRepository, PasskeyRepository, SessionRepository, UserRepository,
    WalletRepository,
};

use super::WebAuthnAuthService;

impl<R> WebAuthnAuthService<R>
where
    R: UserRepository
        + DeviceRepository
        + SessionRepository
        + PasskeyRepository
        + WalletRepository
        + ChallengeRepository,
{
    /// Get all active devices for a user.
    ///
    /// Requires a valid session for authentication.
    /// Returns sanitized DeviceInfo (without encrypted keys) for active devices only.
    pub async fn get_devices(&self, session_id: SessionId) -> Result<Vec<DeviceInfo>> {
        let (user_info, _session) = self.validate_session(session_id).await?;

        let devices = self.repo.get_devices_for_user(user_info.id).await?;

        // Filter to active devices only and convert to DeviceInfo
        Ok(devices
            .iter()
            .filter(|d| d.is_active)
            .map(DeviceInfo::from)
            .collect())
    }

    /// Revoke a device (removes its encrypted key, invalidates sessions).
    ///
    /// Requires a valid session for authentication.
    /// Cannot revoke the device associated with the current session - use logout instead.
    pub async fn revoke_device(&self, session_id: SessionId, device_id: DeviceId) -> Result<()> {
        let (user_info, session) = self.validate_session(session_id).await?;

        // Cannot revoke the device you're currently using
        if session.device_id == device_id {
            return Err(AuthError::CannotRevokeCurrentDevice);
        }

        // Verify the device belongs to this user
        let device = self
            .repo
            .get_device(device_id)
            .await?
            .ok_or(AuthError::DeviceNotFound(device_id.to_string()))?;

        if device.user_id != user_info.id {
            return Err(AuthError::DeviceNotFound(device_id.to_string()));
        }

        // Delete all sessions for this device
        self.repo.delete_sessions_for_device(device_id).await?;

        // Deactivate the device
        self.repo.deactivate_device(device_id).await
    }

    /// Resolve the device id a client sent on login into a device we can reuse.
    ///
    /// Returns `None` when the id is unusable — unknown, owned by someone else,
    /// or revoked — so the caller mints a fresh device instead. Deliberately not
    /// an error: by the time login calls this the credential has already been
    /// verified, so the id is only a hint about which device record to attach the
    /// session to. A hint that no longer applies is the same as no hint.
    ///
    /// It used to return `DeviceNotFound` for all three cases, which locked users
    /// out: the client keeps one id per browser in localStorage and
    /// never clears it on rejection, so it resent the same rejected id forever.
    /// Anyone with two accounts in one browser could only recover by clearing
    /// storage by hand.
    pub(crate) async fn reusable_device(
        &self,
        user_id: UserId,
        provided: Option<DeviceId>,
    ) -> Result<Option<Device>> {
        let Some(id) = provided else {
            return Ok(None);
        };

        match self.repo.get_device(id).await? {
            Some(d) if d.user_id == user_id && d.is_active => Ok(Some(d)),
            // Wrong owner and revoked are not distinguished in the log on
            // purpose: both mean "stale hint", and naming the owner of a device
            // id would leak across accounts.
            Some(_) => {
                tracing::info!(device_id = %id, "stale device id on login; creating a new device");
                Ok(None)
            }
            None => {
                tracing::info!(device_id = %id, "unknown device id on login; creating a new device");
                Ok(None)
            }
        }
    }

    /// Pick the device a login with no reusable device attaches its session to.
    ///
    /// Below the cap this registers a new device. At the cap it re-uses the
    /// least-recently-used active device instead of refusing: the credential has
    /// already been verified, and the only remedy for a full account (revoking a
    /// device) needs a session, which needs a login. Refusing here made the cap a
    /// permanent lockout. Re-using keeps the number of stored device records
    /// bounded, which is what the cap is for.
    ///
    /// The reclaimed record takes the new name and type, so the device list shows
    /// what last used it.
    pub(crate) async fn device_for_new_login(
        &self,
        user: &crate::models::User,
        name: String,
        device_type: DeviceType,
    ) -> Result<DeviceId> {
        let active_count = self.repo.count_active_devices(user.id).await?;

        if active_count >= self.config.max_devices_per_user {
            let lru = self
                .repo
                .get_devices_for_user(user.id)
                .await?
                .into_iter()
                .filter(|d| d.is_active)
                .min_by_key(|d| d.last_used_at.unwrap_or(d.created_at));

            if let Some(mut device) = lru {
                // A warning, and carrying the account: the device list is the only
                // place a user could notice a machine that is not theirs, and an
                // attach to a full account no longer adds a row there. Ids only -
                // never the key blob or a session token.
                tracing::warn!(
                    user_id = %user.id,
                    device_id = %device.id,
                    "device cap reached on login; re-using least recently used device"
                );
                device.name = name;
                device.device_type = device_type;
                device.encrypted_symmetric_key = user.encrypted_symmetric_key.clone();
                device.kdf_params = user.kdf_params.clone();
                device.last_used_at = Some(chrono::Utc::now());
                let id = device.id;
                self.repo.update_device(&device).await?;
                return Ok(id);
            }
            // A cap of zero leaves nothing to re-use; that is a configuration
            // that forbids devices, so it still refuses.
            return Err(AuthError::MaxDevicesReached(
                self.config.max_devices_per_user,
            ));
        }

        let device = Device::new(
            user.id,
            name,
            device_type,
            user.encrypted_symmetric_key.clone(),
            user.kdf_params.clone(),
        );
        let id = device.id;
        self.repo.create_device(&device).await?;
        Ok(id)
    }
}
