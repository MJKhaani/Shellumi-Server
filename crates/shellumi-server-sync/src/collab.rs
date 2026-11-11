//! Team vault collaboration, RBAC matrix enforcement, one-time invitations,
//! recipient-wrapped key envelopes, and cryptographic audit trail.

use rand::RngCore;
use sha2::{Digest, Sha256};
use shellumi_server_domain::{
    AuditEvent, DomainError, VaultInvite, VaultKeyEnvelope, VaultMember, VaultRole,
};
use shellumi_server_protocol::{
    AcceptInviteRequest, AcceptInviteResponse, AddVaultMemberRequest, AuditEventResponse,
    AuditLogResponse, CreateInviteRequest, InviteListResponse, InviteResponse,
    KeyEnvelopeListResponse, KeyEnvelopeResponse, PublishKeyEnvelopesRequest,
    RotateKeyEpochRequest, RotateKeyEpochResponse, VaultMemberListResponse, VaultMemberResponse,
};
use shellumi_server_store::Store;
use uuid::Uuid;

use crate::SyncEngine;

impl<S: Store> SyncEngine<S> {
    /// Lists all members of a vault.
    /// Accessible by any member of the vault (Owner, Administrator, Editor, Viewer).
    pub async fn list_members(
        &self,
        caller_user_id: Uuid,
        vault_id: Uuid,
    ) -> Result<VaultMemberListResponse, DomainError> {
        let vault = self
            .store
            .find_vault_by_id(vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let _caller_role = self
            .store
            .get_vault_member_role(vault_id, caller_user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        let members = self.store.list_vault_members(vault_id).await?;
        let mut responses = Vec::with_capacity(members.len());
        for m in members {
            let username = self
                .store
                .find_user_by_id(m.user_id)
                .await?
                .map(|u| u.username)
                .unwrap_or_else(|| "unknown".to_string());
            responses.push(VaultMemberResponse {
                vault_id: m.vault_id,
                user_id: m.user_id,
                username,
                role: m.role.as_str().to_string(),
                joined_at: m.joined_at,
            });
        }

        Ok(VaultMemberListResponse { members: responses })
    }

    /// Adds or updates a vault member's role.
    /// Enforces role hierarchy and last-owner protection.
    pub async fn add_or_update_member(
        &self,
        caller_user_id: Uuid,
        vault_id: Uuid,
        req: AddVaultMemberRequest,
    ) -> Result<VaultMemberResponse, DomainError> {
        let vault = self
            .store
            .find_vault_by_id(vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let caller_role = self
            .store
            .get_vault_member_role(vault_id, caller_user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if !caller_role.can_admin() {
            return Err(DomainError::PermissionDenied(
                "Only Owners and Administrators can manage members".to_string(),
            ));
        }

        let target_role = match req.role.to_lowercase().as_str() {
            "owner" => VaultRole::Owner,
            "admin" | "administrator" => VaultRole::Administrator,
            "editor" => VaultRole::Editor,
            "viewer" => VaultRole::Viewer,
            _ => {
                return Err(DomainError::InvalidInput(format!(
                    "Invalid vault role: {}",
                    req.role
                )))
            }
        };

        if caller_role == VaultRole::Administrator
            && matches!(target_role, VaultRole::Owner | VaultRole::Administrator)
        {
            return Err(DomainError::PermissionDenied(
                "Administrators can only assign Editor or Viewer roles".to_string(),
            ));
        }

        let existing_role = self
            .store
            .get_vault_member_role(vault_id, req.user_id)
            .await?;
        if let Some(current_role) = existing_role {
            if caller_role == VaultRole::Administrator
                && matches!(current_role, VaultRole::Owner | VaultRole::Administrator)
            {
                return Err(DomainError::PermissionDenied(
                    "Administrators cannot modify Owners or other Administrators".to_string(),
                ));
            }
            if current_role == VaultRole::Owner && target_role != VaultRole::Owner {
                let owner_count = self.store.count_vault_owners(vault_id).await?;
                if owner_count <= 1 {
                    return Err(DomainError::CannotRevokeLastOwner);
                }
            }
        }

        let user = self
            .store
            .find_user_by_id(req.user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        let now = chrono::Utc::now().timestamp();
        let member = VaultMember {
            vault_id,
            user_id: user.id,
            role: target_role,
            joined_at: now,
        };
        self.store.add_vault_member(&member).await?;

        let mut audit = AuditEvent {
            id: 0,
            vault_id,
            tenant_id: vault.tenant_id,
            actor_user_id: caller_user_id,
            actor_device_id: None,
            action: "member.add_or_update".to_string(),
            target_type: "user".to_string(),
            target_id: req.user_id.to_string(),
            details: Some(format!("role={}", target_role.as_str())),
            predecessor_hash: String::new(),
            event_hash: String::new(),
            created_at: now,
        };
        self.store.append_audit_event(&mut audit).await?;

        Ok(VaultMemberResponse {
            vault_id,
            user_id: req.user_id,
            username: user.username,
            role: target_role.as_str().to_string(),
            joined_at: now,
        })
    }

    /// Removes a member from a vault.
    /// Prevents revoking the last owner and respects administrative hierarchy.
    pub async fn remove_member(
        &self,
        caller_user_id: Uuid,
        vault_id: Uuid,
        target_user_id: Uuid,
    ) -> Result<(), DomainError> {
        let vault = self
            .store
            .find_vault_by_id(vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let caller_role = self
            .store
            .get_vault_member_role(vault_id, caller_user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if !caller_role.can_admin() {
            return Err(DomainError::PermissionDenied(
                "Only Owners and Administrators can remove members".to_string(),
            ));
        }

        let target_role = self
            .store
            .get_vault_member_role(vault_id, target_user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if caller_role == VaultRole::Administrator
            && matches!(target_role, VaultRole::Owner | VaultRole::Administrator)
        {
            return Err(DomainError::PermissionDenied(
                "Administrators cannot remove Owners or other Administrators".to_string(),
            ));
        }

        if target_role == VaultRole::Owner {
            let owner_count = self.store.count_vault_owners(vault_id).await?;
            if owner_count <= 1 {
                return Err(DomainError::CannotRevokeLastOwner);
            }
        }

        self.store
            .remove_vault_member(vault_id, target_user_id)
            .await?;
        let now = chrono::Utc::now().timestamp();

        let mut audit = AuditEvent {
            id: 0,
            vault_id,
            tenant_id: vault.tenant_id,
            actor_user_id: caller_user_id,
            actor_device_id: None,
            action: "member.remove".to_string(),
            target_type: "user".to_string(),
            target_id: target_user_id.to_string(),
            details: None,
            predecessor_hash: String::new(),
            event_hash: String::new(),
            created_at: now,
        };
        self.store.append_audit_event(&mut audit).await?;

        Ok(())
    }

    /// Creates a one-time scoped invitation.
    /// Generates a 256-bit cryptographically secure token and stores only its SHA-256 hash.
    pub async fn create_invite(
        &self,
        caller_user_id: Uuid,
        vault_id: Uuid,
        req: CreateInviteRequest,
    ) -> Result<InviteResponse, DomainError> {
        let vault = self
            .store
            .find_vault_by_id(vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let caller_role = self
            .store
            .get_vault_member_role(vault_id, caller_user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if !caller_role.can_admin() {
            return Err(DomainError::PermissionDenied(
                "Only Owners and Administrators can create invitations".to_string(),
            ));
        }

        let role = match req.role.to_lowercase().as_str() {
            "owner" => VaultRole::Owner,
            "admin" | "administrator" => VaultRole::Administrator,
            "editor" => VaultRole::Editor,
            "viewer" => VaultRole::Viewer,
            _ => {
                return Err(DomainError::InvalidInput(format!(
                    "Invalid vault role: {}",
                    req.role
                )))
            }
        };

        if caller_role == VaultRole::Administrator
            && matches!(role, VaultRole::Owner | VaultRole::Administrator)
        {
            return Err(DomainError::PermissionDenied(
                "Administrators can only invite Editors or Viewers".to_string(),
            ));
        }

        let mut token_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut token_bytes);
        let raw_token = hex::encode(token_bytes);
        let token_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));

        let now = chrono::Utc::now().timestamp();
        let expires_in = req.ttl_secs.unwrap_or(86400) as i64;
        let expires_at = now + expires_in;
        let invite_id = Uuid::new_v4();

        let invite = VaultInvite {
            id: invite_id,
            vault_id,
            inviter_user_id: caller_user_id,
            role,
            invite_token_hash: token_hash,
            recipient_email: req.recipient_email.clone(),
            expires_at,
            accepted_at: None,
            accepted_by_user_id: None,
            revoked_at: None,
            created_at: now,
        };
        self.store.create_invite(&invite).await?;

        let mut audit = AuditEvent {
            id: 0,
            vault_id,
            tenant_id: vault.tenant_id,
            actor_user_id: caller_user_id,
            actor_device_id: None,
            action: "invite.create".to_string(),
            target_type: "invite".to_string(),
            target_id: invite_id.to_string(),
            details: Some(format!("role={}", role.as_str())),
            predecessor_hash: String::new(),
            event_hash: String::new(),
            created_at: now,
        };
        self.store.append_audit_event(&mut audit).await?;

        Ok(InviteResponse {
            invite_id,
            vault_id,
            role: role.as_str().to_string(),
            invite_token: Some(raw_token),
            recipient_email: req.recipient_email,
            expires_at,
            created_at: now,
        })
    }

    /// Lists active, unexpired invitations for a vault.
    pub async fn list_invites(
        &self,
        caller_user_id: Uuid,
        vault_id: Uuid,
    ) -> Result<InviteListResponse, DomainError> {
        let vault = self
            .store
            .find_vault_by_id(vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let caller_role = self
            .store
            .get_vault_member_role(vault_id, caller_user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if !caller_role.can_admin() {
            return Err(DomainError::PermissionDenied(
                "Only Owners and Administrators can list invitations".to_string(),
            ));
        }

        let active = self.store.list_active_invites(vault_id).await?;
        let responses = active
            .into_iter()
            .map(|inv| InviteResponse {
                invite_id: inv.id,
                vault_id: inv.vault_id,
                role: inv.role.as_str().to_string(),
                invite_token: None,
                recipient_email: inv.recipient_email,
                expires_at: inv.expires_at,
                created_at: inv.created_at,
            })
            .collect();

        Ok(InviteListResponse { invites: responses })
    }

    /// Revokes an existing invitation.
    pub async fn revoke_invite(
        &self,
        caller_user_id: Uuid,
        vault_id: Uuid,
        invite_id: Uuid,
    ) -> Result<(), DomainError> {
        let vault = self
            .store
            .find_vault_by_id(vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let caller_role = self
            .store
            .get_vault_member_role(vault_id, caller_user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if !caller_role.can_admin() {
            return Err(DomainError::PermissionDenied(
                "Only Owners and Administrators can revoke invitations".to_string(),
            ));
        }

        let invite = self
            .store
            .find_invite_by_id(invite_id)
            .await?
            .ok_or(DomainError::InviteNotFound)?;

        if invite.vault_id != vault_id {
            return Err(DomainError::InviteNotFound);
        }

        let now = chrono::Utc::now().timestamp();
        self.store.revoke_invite(invite_id, now).await?;

        let mut audit = AuditEvent {
            id: 0,
            vault_id,
            tenant_id: vault.tenant_id,
            actor_user_id: caller_user_id,
            actor_device_id: None,
            action: "invite.revoke".to_string(),
            target_type: "invite".to_string(),
            target_id: invite_id.to_string(),
            details: None,
            predecessor_hash: String::new(),
            event_hash: String::new(),
            created_at: now,
        };
        self.store.append_audit_event(&mut audit).await?;

        Ok(())
    }

    /// Accepts an invitation with token hash validation.
    pub async fn accept_invite(
        &self,
        caller_user_id: Uuid,
        req: AcceptInviteRequest,
    ) -> Result<AcceptInviteResponse, DomainError> {
        let token_hash = hex::encode(Sha256::digest(req.invite_token.trim().as_bytes()));
        let invite = self
            .store
            .find_invite_by_hash(&token_hash)
            .await?
            .ok_or(DomainError::InviteNotFound)?;
        let now = chrono::Utc::now().timestamp();

        if invite.revoked_at.is_some() {
            return Err(DomainError::InviteRevoked);
        }
        if invite.accepted_at.is_some() {
            return Err(DomainError::InviteAlreadyAccepted);
        }
        if invite.expires_at <= now {
            return Err(DomainError::InviteExpired);
        }

        let vault = self
            .store
            .find_vault_by_id(invite.vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let member = VaultMember {
            vault_id: invite.vault_id,
            user_id: caller_user_id,
            role: invite.role,
            joined_at: now,
        };
        self.store.add_vault_member(&member).await?;
        self.store
            .accept_invite(invite.id, caller_user_id, now)
            .await?;

        let mut audit = AuditEvent {
            id: 0,
            vault_id: invite.vault_id,
            tenant_id: vault.tenant_id,
            actor_user_id: caller_user_id,
            actor_device_id: None,
            action: "invite.accept".to_string(),
            target_type: "invite".to_string(),
            target_id: invite.id.to_string(),
            details: Some(format!("role={}", invite.role.as_str())),
            predecessor_hash: String::new(),
            event_hash: String::new(),
            created_at: now,
        };
        self.store.append_audit_event(&mut audit).await?;

        Ok(AcceptInviteResponse {
            vault_id: invite.vault_id,
            role: invite.role.as_str().to_string(),
        })
    }

    /// Publishes recipient-wrapped key envelopes for a given key epoch.
    pub async fn publish_key_envelopes(
        &self,
        caller_user_id: Uuid,
        caller_device_id: Uuid,
        vault_id: Uuid,
        req: PublishKeyEnvelopesRequest,
    ) -> Result<usize, DomainError> {
        let vault = self
            .store
            .find_vault_by_id(vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let caller_role = self
            .store
            .get_vault_member_role(vault_id, caller_user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if !caller_role.can_write() {
            return Err(DomainError::PermissionDenied(
                "Viewers cannot publish key envelopes".to_string(),
            ));
        }

        let device = self
            .store
            .find_device_by_id(caller_device_id)
            .await?
            .ok_or(DomainError::DeviceNotFound)?;
        if device.user_id != caller_user_id {
            return Err(DomainError::PermissionDenied(
                "Device does not belong to the authenticated user".to_string(),
            ));
        }
        if device.revoked_at.is_some() {
            return Err(DomainError::DeviceRevoked);
        }

        let now = chrono::Utc::now().timestamp();
        let mut envelopes = Vec::with_capacity(req.envelopes.len());
        for item in req.envelopes {
            let recipient = self
                .store
                .find_device_by_id(item.recipient_device_id)
                .await?
                .ok_or(DomainError::DeviceNotFound)?;
            if recipient.revoked_at.is_some() {
                return Err(DomainError::DeviceRevoked);
            }
            if item.wrapped_dek.trim().is_empty() {
                return Err(DomainError::InvalidInput(
                    "wrapped_dek must not be empty".to_string(),
                ));
            }
            envelopes.push(VaultKeyEnvelope {
                vault_id,
                epoch: req.epoch,
                recipient_device_id: item.recipient_device_id,
                sender_device_id: caller_device_id,
                wrapped_dek: item.wrapped_dek,
                key_agreement_ephemeral_pk: item.key_agreement_ephemeral_pk,
                created_at: now,
            });
        }

        let count = envelopes.len();
        self.store.save_envelopes(&envelopes).await?;

        let mut audit = AuditEvent {
            id: 0,
            vault_id,
            tenant_id: vault.tenant_id,
            actor_user_id: caller_user_id,
            actor_device_id: Some(caller_device_id),
            action: "keys.publish_envelopes".to_string(),
            target_type: "epoch".to_string(),
            target_id: req.epoch.to_string(),
            details: Some(format!("count={count}")),
            predecessor_hash: String::new(),
            event_hash: String::new(),
            created_at: now,
        };
        self.store.append_audit_event(&mut audit).await?;

        Ok(count)
    }

    /// Fetches key envelopes wrapped strictly for the calling device.
    /// Devices can never fetch envelopes wrapped for other devices.
    pub async fn get_envelopes_for_device(
        &self,
        caller_user_id: Uuid,
        calling_device_id: Uuid,
        vault_id: Uuid,
        epoch: Option<u32>,
    ) -> Result<KeyEnvelopeListResponse, DomainError> {
        let vault = self
            .store
            .find_vault_by_id(vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let _caller_role = self
            .store
            .get_vault_member_role(vault_id, caller_user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        let device = self
            .store
            .find_device_by_id(calling_device_id)
            .await?
            .ok_or(DomainError::DeviceNotFound)?;
        if device.user_id != caller_user_id {
            return Err(DomainError::PermissionDenied(
                "Device does not belong to the authenticated user".to_string(),
            ));
        }
        if device.revoked_at.is_some() {
            return Err(DomainError::DeviceRevoked);
        }

        let envelopes = self
            .store
            .get_envelopes_for_device(vault_id, calling_device_id, epoch)
            .await?;
        let responses = envelopes
            .into_iter()
            .map(|e| KeyEnvelopeResponse {
                vault_id: e.vault_id,
                epoch: e.epoch,
                recipient_device_id: e.recipient_device_id,
                sender_device_id: e.sender_device_id,
                wrapped_dek: e.wrapped_dek,
                key_agreement_ephemeral_pk: e.key_agreement_ephemeral_pk,
                created_at: e.created_at,
            })
            .collect();

        Ok(KeyEnvelopeListResponse {
            envelopes: responses,
        })
    }

    /// Rotates the vault key epoch.
    /// Validates that new_epoch > current_epoch, stores wraps, updates active epoch, and audits.
    pub async fn rotate_key_epoch(
        &self,
        caller_user_id: Uuid,
        caller_device_id: Uuid,
        vault_id: Uuid,
        req: RotateKeyEpochRequest,
    ) -> Result<RotateKeyEpochResponse, DomainError> {
        let vault = self
            .store
            .find_vault_by_id(vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let caller_role = self
            .store
            .get_vault_member_role(vault_id, caller_user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if !caller_role.can_admin() {
            return Err(DomainError::PermissionDenied(
                "Only Owners and Administrators can rotate key epochs".to_string(),
            ));
        }

        let device = self
            .store
            .find_device_by_id(caller_device_id)
            .await?
            .ok_or(DomainError::DeviceNotFound)?;
        if device.user_id != caller_user_id {
            return Err(DomainError::PermissionDenied(
                "Device does not belong to the authenticated user".to_string(),
            ));
        }
        if device.revoked_at.is_some() {
            return Err(DomainError::DeviceRevoked);
        }

        if req.new_epoch <= vault.active_key_epoch {
            return Err(DomainError::StaleKeyEpoch {
                current: vault.active_key_epoch,
                provided: req.new_epoch,
            });
        }

        let now = chrono::Utc::now().timestamp();
        let mut envelopes = Vec::with_capacity(req.envelopes.len());
        for item in req.envelopes {
            let recipient = self
                .store
                .find_device_by_id(item.recipient_device_id)
                .await?
                .ok_or(DomainError::DeviceNotFound)?;
            if recipient.revoked_at.is_some() {
                return Err(DomainError::DeviceRevoked);
            }
            envelopes.push(VaultKeyEnvelope {
                vault_id,
                epoch: req.new_epoch,
                recipient_device_id: item.recipient_device_id,
                sender_device_id: caller_device_id,
                wrapped_dek: item.wrapped_dek,
                key_agreement_ephemeral_pk: item.key_agreement_ephemeral_pk,
                created_at: now,
            });
        }

        let enrolled_envelopes = envelopes.len();
        self.store.save_envelopes(&envelopes).await?;
        self.store
            .update_vault_key_epoch(vault_id, req.new_epoch)
            .await?;

        let mut audit = AuditEvent {
            id: 0,
            vault_id,
            tenant_id: vault.tenant_id,
            actor_user_id: caller_user_id,
            actor_device_id: Some(caller_device_id),
            action: "keys.rotate_epoch".to_string(),
            target_type: "epoch".to_string(),
            target_id: req.new_epoch.to_string(),
            details: Some(format!("envelopes={enrolled_envelopes}")),
            predecessor_hash: String::new(),
            event_hash: String::new(),
            created_at: now,
        };
        self.store.append_audit_event(&mut audit).await?;

        Ok(RotateKeyEpochResponse {
            vault_id,
            active_key_epoch: req.new_epoch,
            enrolled_envelopes,
        })
    }

    /// Fetches the cryptographic audit log for a vault.
    /// Restricted to Owners and Administrators.
    pub async fn get_audit_log(
        &self,
        caller_user_id: Uuid,
        vault_id: Uuid,
        limit: usize,
        offset: usize,
    ) -> Result<AuditLogResponse, DomainError> {
        let vault = self
            .store
            .find_vault_by_id(vault_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        if vault.deleted_at.is_some() {
            return Err(DomainError::NotFound);
        }

        let caller_role = self
            .store
            .get_vault_member_role(vault_id, caller_user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if !caller_role.can_admin() {
            return Err(DomainError::PermissionDenied(
                "Only Owners and Administrators can view audit logs".to_string(),
            ));
        }

        let limit = if limit == 0 || limit > 100 { 50 } else { limit };
        let events = self
            .store
            .list_audit_events(vault_id, limit, offset)
            .await?;
        let responses = events
            .into_iter()
            .map(|e| AuditEventResponse {
                id: e.id,
                vault_id: e.vault_id,
                actor_user_id: e.actor_user_id,
                actor_device_id: e.actor_device_id,
                action: e.action,
                target_type: e.target_type,
                target_id: e.target_id,
                details: e.details,
                predecessor_hash: e.predecessor_hash,
                event_hash: e.event_hash,
                created_at: e.created_at,
            })
            .collect();

        Ok(AuditLogResponse {
            vault_id,
            events: responses,
        })
    }
}
