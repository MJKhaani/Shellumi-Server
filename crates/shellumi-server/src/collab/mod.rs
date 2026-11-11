//! Live terminal collaboration engine and real-time signaling / ciphertext relay.

use futures_util::stream::Stream;
use shellumi_server_domain::{
    CollabMode, CollabParticipant, CollabRole, CollabSession, DomainError,
};
use shellumi_server_protocol::{
    CollabFrame, CollabFrameType, CollabParticipantResponse, CollabSessionResponse,
    CreateCollabSessionRequest, EnrollParticipantRequest, GrantControlRequest,
    SendCollabFrameRequest,
};
use shellumi_server_store::CollabRepository;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

const DEFAULT_COLLAB_TTL_SECS: u64 = 3600; // 1 hour
const MIN_COLLAB_TTL_SECS: u64 = 60; // 1 minute
const MAX_COLLAB_TTL_SECS: u64 = 86400; // 24 hours
const CHANNEL_CAPACITY: usize = 256;

/// In-memory broadcast and signaling hub for live collaboration sessions.
pub struct CollabHub<S: CollabRepository + 'static> {
    store: Arc<S>,
    channels: Arc<RwLock<HashMap<Uuid, broadcast::Sender<CollabFrame>>>>,
    sequences: Arc<RwLock<HashMap<Uuid, u64>>>,
}

impl<S: CollabRepository + 'static> CollabHub<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            channels: Arc::new(RwLock::new(HashMap::new())),
            sequences: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn store(&self) -> &Arc<S> {
        &self.store
    }

    /// Creates a new live terminal collaboration session.
    pub async fn create_session(
        &self,
        host_user_id: Uuid,
        host_device_id: Uuid,
        req: CreateCollabSessionRequest,
        now: i64,
    ) -> Result<CollabSessionResponse, DomainError> {
        let title = req.title.trim().to_string();
        if title.is_empty() {
            return Err(DomainError::InvalidInput(
                "Session title cannot be empty".to_string(),
            ));
        }

        let mode = match req.mode.to_lowercase().as_str() {
            "controllable" => CollabMode::Controllable,
            "read_only" => CollabMode::ReadOnly,
            _ => {
                return Err(DomainError::InvalidInput(
                    "Invalid session mode: must be 'read_only' or 'controllable'".to_string(),
                ))
            }
        };

        let ttl = req
            .ttl_secs
            .unwrap_or(DEFAULT_COLLAB_TTL_SECS)
            .clamp(MIN_COLLAB_TTL_SECS, MAX_COLLAB_TTL_SECS);

        let session_id = Uuid::now_v7();
        let session = CollabSession {
            id: session_id,
            host_user_id,
            host_device_id,
            title,
            mode,
            active_writer_user_id: None,
            active_writer_device_id: None,
            lease_token: 1,
            lease_expires_at: None,
            expires_at: now + ttl as i64,
            terminated_at: None,
            created_at: now,
        };

        let host_participant = CollabParticipant {
            session_id,
            user_id: host_user_id,
            device_id: host_device_id,
            role: CollabRole::Host,
            joined_at: now,
            revoked_at: None,
        };

        self.store
            .create_collab_session(&session, &host_participant)
            .await?;

        // Initialize sequence counter
        {
            let mut seqs = self.sequences.write().await;
            seqs.insert(session_id, 0);
        }

        Ok(Self::session_to_response(&session))
    }

    /// Lists active collaboration sessions for a given user.
    pub async fn list_active_sessions(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<CollabSessionResponse>, DomainError> {
        let sessions = self
            .store
            .list_active_collab_sessions_for_user(user_id)
            .await?;
        Ok(sessions.iter().map(Self::session_to_response).collect())
    }

    /// Gets details of a session if the user is an enrolled participant or host.
    pub async fn get_session(
        &self,
        session_id: Uuid,
        user_id: Uuid,
    ) -> Result<CollabSessionResponse, DomainError> {
        let session = self
            .store
            .find_collab_session(session_id)
            .await?
            .ok_or(DomainError::CollabSessionNotFound(session_id))?;

        if session.host_user_id != user_id {
            // Check if user is an active participant
            let participants = self.store.list_collab_participants(session_id).await?;
            let is_enrolled = participants
                .iter()
                .any(|p| p.user_id == user_id && p.revoked_at.is_none());
            if !is_enrolled {
                return Err(DomainError::CollabSessionNotFound(session_id));
            }
        }

        Ok(Self::session_to_response(&session))
    }

    /// Enrolls a participant into the session (host only).
    pub async fn enroll_participant(
        &self,
        session_id: Uuid,
        host_user_id: Uuid,
        req: EnrollParticipantRequest,
        now: i64,
    ) -> Result<CollabParticipantResponse, DomainError> {
        let session = self
            .store
            .find_collab_session(session_id)
            .await?
            .ok_or(DomainError::CollabSessionNotFound(session_id))?;

        if session.host_user_id != host_user_id {
            return Err(DomainError::NotSessionHost);
        }

        if session.terminated_at.is_some() {
            return Err(DomainError::CollabSessionTerminated);
        }

        if now > session.expires_at {
            return Err(DomainError::CollabSessionExpired);
        }

        let role = match req.role.to_lowercase().as_str() {
            "writer" => CollabRole::Writer,
            "viewer" => CollabRole::Viewer,
            _ => {
                return Err(DomainError::InvalidInput(
                    "Invalid participant role: must be 'writer' or 'viewer'".to_string(),
                ))
            }
        };

        let participant = CollabParticipant {
            session_id,
            user_id: req.user_id,
            device_id: req.device_id,
            role,
            joined_at: now,
            revoked_at: None,
        };

        self.store.add_collab_participant(&participant).await?;
        Ok(Self::participant_to_response(&participant))
    }

    /// Lists participants of a session.
    pub async fn list_participants(
        &self,
        session_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<CollabParticipantResponse>, DomainError> {
        // Authorization check: must be host or participant
        let _ = self.get_session(session_id, user_id).await?;

        let participants = self.store.list_collab_participants(session_id).await?;
        Ok(participants
            .iter()
            .map(Self::participant_to_response)
            .collect())
    }

    /// Grants write control to a participant (host only).
    pub async fn grant_control(
        &self,
        session_id: Uuid,
        host_user_id: Uuid,
        req: GrantControlRequest,
        now: i64,
    ) -> Result<CollabSessionResponse, DomainError> {
        let session = self
            .store
            .find_collab_session(session_id)
            .await?
            .ok_or(DomainError::CollabSessionNotFound(session_id))?;

        if session.host_user_id != host_user_id {
            return Err(DomainError::NotSessionHost);
        }

        if session.terminated_at.is_some() {
            return Err(DomainError::CollabSessionTerminated);
        }

        if now > session.expires_at {
            return Err(DomainError::CollabSessionExpired);
        }

        if session.mode != CollabMode::Controllable {
            return Err(DomainError::InvalidInput(
                "Cannot grant write control in a read-only collaboration session".to_string(),
            ));
        }

        // Verify target participant exists and is active
        let target = self
            .store
            .find_collab_participant(session_id, req.target_user_id, req.target_device_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if target.revoked_at.is_some() {
            return Err(DomainError::ParticipantRevoked);
        }

        let lease_expires_at = req.ttl_secs.map(|ttl| now + ttl as i64);

        let new_token = self
            .store
            .grant_collab_writer_lease(
                session_id,
                req.target_user_id,
                req.target_device_id,
                lease_expires_at,
            )
            .await?;

        // Allocate sequence for ControlGranted frame
        let sequence = self.next_sequence(session_id).await;
        let control_frame = CollabFrame {
            session_id,
            sequence,
            frame_type: CollabFrameType::ControlGranted,
            sender_user_id: host_user_id,
            sender_device_id: session.host_device_id,
            lease_token: Some(new_token),
            encrypted_envelope: serde_json::json!({
                "granted_to_user_id": req.target_user_id,
                "granted_to_device_id": req.target_device_id,
                "lease_token": new_token,
                "lease_expires_at": lease_expires_at,
            })
            .to_string(),
            created_at: now,
        };

        self.store.append_collab_frame(&control_frame).await?;
        self.broadcast_frame(&control_frame).await;

        let updated = self
            .store
            .find_collab_session(session_id)
            .await?
            .ok_or(DomainError::CollabSessionNotFound(session_id))?;

        Ok(Self::session_to_response(&updated))
    }

    /// Revokes write control back to host (host only).
    pub async fn revoke_control(
        &self,
        session_id: Uuid,
        host_user_id: Uuid,
        now: i64,
    ) -> Result<CollabSessionResponse, DomainError> {
        let session = self
            .store
            .find_collab_session(session_id)
            .await?
            .ok_or(DomainError::CollabSessionNotFound(session_id))?;

        if session.host_user_id != host_user_id {
            return Err(DomainError::NotSessionHost);
        }

        if session.terminated_at.is_some() {
            return Err(DomainError::CollabSessionTerminated);
        }

        let new_token = self.store.revoke_collab_writer_lease(session_id).await?;

        // Allocate sequence for ControlRevoked frame
        let sequence = self.next_sequence(session_id).await;
        let control_frame = CollabFrame {
            session_id,
            sequence,
            frame_type: CollabFrameType::ControlRevoked,
            sender_user_id: host_user_id,
            sender_device_id: session.host_device_id,
            lease_token: Some(new_token),
            encrypted_envelope: serde_json::json!({
                "revoked": true,
                "lease_token": new_token,
            })
            .to_string(),
            created_at: now,
        };

        self.store.append_collab_frame(&control_frame).await?;
        self.broadcast_frame(&control_frame).await;

        let updated = self
            .store
            .find_collab_session(session_id)
            .await?
            .ok_or(DomainError::CollabSessionNotFound(session_id))?;

        Ok(Self::session_to_response(&updated))
    }

    /// Emergency terminates the session (host only).
    pub async fn terminate_session(
        &self,
        session_id: Uuid,
        host_user_id: Uuid,
        now: i64,
    ) -> Result<(), DomainError> {
        let session = self
            .store
            .find_collab_session(session_id)
            .await?
            .ok_or(DomainError::CollabSessionNotFound(session_id))?;

        if session.host_user_id != host_user_id {
            return Err(DomainError::NotSessionHost);
        }

        self.store.terminate_collab_session(session_id, now).await?;

        // Broadcast Terminated frame
        let sequence = self.next_sequence(session_id).await;
        let term_frame = CollabFrame {
            session_id,
            sequence,
            frame_type: CollabFrameType::Terminated,
            sender_user_id: host_user_id,
            sender_device_id: session.host_device_id,
            lease_token: None,
            encrypted_envelope: serde_json::json!({ "terminated": true }).to_string(),
            created_at: now,
        };

        self.store.append_collab_frame(&term_frame).await?;
        self.broadcast_frame(&term_frame).await;

        // Clean up broadcast channel
        let mut channels = self.channels.write().await;
        channels.remove(&session_id);

        Ok(())
    }

    /// Submits a client-encrypted frame to the relay.
    pub async fn send_frame(
        &self,
        session_id: Uuid,
        sender_user_id: Uuid,
        sender_device_id: Uuid,
        req: SendCollabFrameRequest,
        now: i64,
    ) -> Result<CollabFrame, DomainError> {
        let session = self
            .store
            .find_collab_session(session_id)
            .await?
            .ok_or(DomainError::CollabSessionNotFound(session_id))?;

        if session.terminated_at.is_some() {
            return Err(DomainError::CollabSessionTerminated);
        }

        if now > session.expires_at {
            return Err(DomainError::CollabSessionExpired);
        }

        // Verify sender participant enrollment
        let participant = self
            .store
            .find_collab_participant(session_id, sender_user_id, sender_device_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if participant.revoked_at.is_some() {
            return Err(DomainError::ParticipantRevoked);
        }

        // Enforce role policies and single-writer fencing token
        match req.frame_type {
            CollabFrameType::Output => {
                // Terminal output may ONLY be emitted by the host!
                if sender_user_id != session.host_user_id
                    || sender_device_id != session.host_device_id
                {
                    return Err(DomainError::PermissionDenied(
                        "Only the session host can emit terminal output frames".to_string(),
                    ));
                }
            }
            CollabFrameType::Input => {
                // Keystrokes / PTY input may ONLY be emitted if session is controllable
                if session.mode != CollabMode::Controllable {
                    return Err(DomainError::PermissionDenied(
                        "Terminal input is not permitted in a read-only collaboration session"
                            .to_string(),
                    ));
                }

                // Check active writer designation
                let is_writer = session.active_writer_user_id == Some(sender_user_id)
                    && session.active_writer_device_id == Some(sender_device_id);

                if !is_writer {
                    return Err(DomainError::NotAuthorizedWriter);
                }

                // Check monotonic fencing token
                let provided_token = req.lease_token.ok_or(DomainError::NotAuthorizedWriter)?;
                if provided_token != session.lease_token {
                    return Err(DomainError::StaleLeaseToken {
                        current: session.lease_token,
                        provided: provided_token,
                    });
                }

                // Check lease expiry if set
                if let Some(exp) = session.lease_expires_at {
                    if now > exp {
                        return Err(DomainError::NotAuthorizedWriter);
                    }
                }
            }
            CollabFrameType::Signal => {
                // Signalling / key exchange is allowed for any active enrolled participant
            }
            CollabFrameType::ControlGranted
            | CollabFrameType::ControlRevoked
            | CollabFrameType::Terminated => {
                if sender_user_id != session.host_user_id {
                    return Err(DomainError::NotSessionHost);
                }
            }
        }

        let sequence = self.next_sequence(session_id).await;
        let frame = CollabFrame {
            session_id,
            sequence,
            frame_type: req.frame_type,
            sender_user_id,
            sender_device_id,
            lease_token: req.lease_token,
            encrypted_envelope: req.encrypted_envelope,
            created_at: now,
        };

        self.store.append_collab_frame(&frame).await?;
        self.broadcast_frame(&frame).await;

        Ok(frame)
    }

    /// Polls past frames starting after `since_sequence`.
    pub async fn poll_frames(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        since_sequence: u64,
        limit: usize,
    ) -> Result<Vec<CollabFrame>, DomainError> {
        let _ = self.get_session(session_id, user_id).await?;
        let clamped_limit = limit.clamp(1, 100);
        self.store
            .get_collab_frames(session_id, since_sequence, clamped_limit)
            .await
    }

    /// Subscribes to real-time events for a session.
    pub async fn subscribe(
        &self,
        session_id: Uuid,
        user_id: Uuid,
    ) -> Result<broadcast::Receiver<CollabFrame>, DomainError> {
        let _ = self.get_session(session_id, user_id).await?;

        let mut channels = self.channels.write().await;
        let rx = match channels.get(&session_id) {
            Some(tx) => tx.subscribe(),
            None => {
                let (tx, rx) = broadcast::channel(CHANNEL_CAPACITY);
                channels.insert(session_id, tx);
                rx
            }
        };

        Ok(rx)
    }

    async fn next_sequence(&self, session_id: Uuid) -> u64 {
        let mut seqs = self.sequences.write().await;
        let seq = seqs.entry(session_id).or_insert(0);
        *seq += 1;
        *seq
    }

    async fn broadcast_frame(&self, frame: &CollabFrame) {
        let channels = self.channels.read().await;
        if let Some(tx) = channels.get(&frame.session_id) {
            let _ = tx.send(frame.clone());
        }
    }

    fn session_to_response(s: &CollabSession) -> CollabSessionResponse {
        CollabSessionResponse {
            session_id: s.id,
            host_user_id: s.host_user_id,
            host_device_id: s.host_device_id,
            title: s.title.clone(),
            mode: s.mode.as_str().to_string(),
            active_writer_user_id: s.active_writer_user_id,
            active_writer_device_id: s.active_writer_device_id,
            lease_token: s.lease_token,
            lease_expires_at: s.lease_expires_at,
            expires_at: s.expires_at,
            terminated_at: s.terminated_at,
            created_at: s.created_at,
        }
    }

    fn participant_to_response(p: &CollabParticipant) -> CollabParticipantResponse {
        CollabParticipantResponse {
            session_id: p.session_id,
            user_id: p.user_id,
            device_id: p.device_id,
            role: p.role.as_str().to_string(),
            joined_at: p.joined_at,
            revoked_at: p.revoked_at,
        }
    }
}

/// Converts a broadcast::Receiver into a Stream for Axum SSE.
pub fn into_collab_stream(
    receiver: broadcast::Receiver<CollabFrame>,
) -> impl Stream<Item = Result<CollabFrame, broadcast::error::RecvError>> {
    futures_util::stream::unfold(receiver, |mut rx| async move {
        match rx.recv().await {
            Ok(frame) => Some((Ok(frame), rx)),
            Err(broadcast::error::RecvError::Closed) => None,
            Err(err) => Some((Err(err), rx)),
        }
    })
}
