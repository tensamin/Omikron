use std::time::Duration;

use livekit_api::{
    access_token::{AccessToken, VideoGrants},
    services::room::UpdateParticipantOptions,
};
use livekit_protocol::{ParticipantPermission, TrackSource};
use tau::calls::*;

use super::call_util::LiveKitService;

fn sources(p: &EffectivePermissions) -> Vec<TrackSource> {
    [
        (p.publish_microphone, TrackSource::Microphone),
        (p.publish_camera, TrackSource::Camera),
        (p.publish_screen_share, TrackSource::ScreenShare),
        (p.publish_screen_share_audio, TrackSource::ScreenShareAudio),
    ]
    .into_iter()
    .filter_map(|(allowed, source)| allowed.then_some(source))
    .collect()
}

fn opaque_identity(call: &CallId, principal: &CallPrincipal) -> Result<String, CallError> {
    let bytes = serde_json::to_vec(&(call, principal)).map_err(|_| CallError::InvalidRequest)?;
    Ok(mtp::crypto::sha256(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn room_name(call: &CallId) -> Result<String, CallError> {
    Ok(call.id.to_string())
}

fn participant_permission(effective: &EffectivePermissions) -> ParticipantPermission {
    let sources = sources(effective);
    ParticipantPermission {
        can_publish: !sources.is_empty(),
        can_publish_sources: sources.into_iter().map(|s| s as i32).collect(),
        can_subscribe: effective.receive_media,
        can_publish_data: effective.publish_data,
        can_update_metadata: false,
        ..Default::default()
    }
}

fn needs_credential_gate(effective: &EffectivePermissions) -> bool {
    !effective.publish_microphone
        || !effective.publish_camera
        || !effective.publish_screen_share
        || !effective.publish_screen_share_audio
        || !effective.receive_media
        || !effective.publish_data
}

fn denied_track_sids<'a>(
    participant: &'a livekit_protocol::ParticipantInfo,
    effective: &EffectivePermissions,
) -> Vec<&'a str> {
    let allowed = sources(effective);
    participant
        .tracks
        .iter()
        .filter(|track| {
            !track.muted && !allowed.iter().any(|source| *source as i32 == track.source)
        })
        .map(|track| track.sid.as_str())
        .collect()
}

async fn stop_denied_tracks(
    client: &livekit_api::services::room::RoomClient,
    room: &str,
    participant: &livekit_protocol::ParticipantInfo,
    effective: &EffectivePermissions,
) -> Result<(), CallError> {
    for sid in denied_track_sids(participant, effective) {
        client
            .mute_published_track(room, &participant.identity, sid, true)
            .await
            .map_err(|_| CallError::MediaEnforcementPending)?;
    }
    Ok(())
}

impl LiveKitService {
    pub fn set_call_host_id(&self, id: u64) {
        self.management_owner_id
            .store(id, std::sync::atomic::Ordering::Relaxed);
    }

    async fn publish_metadata(
        &self,
        client: &livekit_api::services::room::RoomClient,
        call: &Call,
    ) -> Result<(), CallError> {
        if self
            .metadata_revisions
            .get(&call.id)
            .is_some_and(|revision| *revision >= call.revision)
        {
            return Ok(());
        }
        let owner = self
            .management_owner_id
            .load(std::sync::atomic::Ordering::Relaxed);
        let Some(authority) = self.legacy_call_bindings.get(&call.id).map(|a| a.clone()) else {
            return Ok(());
        };
        if owner == 0 {
            return Ok(());
        }
        let admins: Vec<_> = call
            .members
            .iter()
            .filter(|m| {
                m.authorized
                    && m.principal.authority == authority
                    && matches!(m.role, CallRole::Owner | CallRole::Moderator)
            })
            .map(|m| m.principal.user_id)
            .collect();
        let metadata=serde_json::to_string(&serde_json::json!({"owner_omikron_id":owner,"admins":admins,
            "anonymous_joining":call.policy.join_policy==JoinPolicy::Guests,"revision":call.revision})).map_err(|_|CallError::InvalidRequest)?;
        client
            .update_room_metadata(&room_name(&call.id)?, &metadata)
            .await
            .map_err(|_| CallError::MediaEnforcementPending)?;
        self.metadata_revisions
            .insert(call.id.clone(), call.revision);
        Ok(())
    }
    /// Register the persisted migration binding before restoring a legacy room.
    /// Numeric identities remain valid only inside this one principal namespace.
    pub fn register_legacy_call(&self, call: CallId, authority: CallAuthority) {
        self.legacy_call_bindings.insert(call, authority);
    }

    fn management_identity(
        &self,
        call: &CallId,
        principal: &CallPrincipal,
    ) -> Result<String, CallError> {
        if let Some(authority) = self.legacy_call_bindings.get(call)
            && *authority == principal.authority
        {
            return Ok(principal.user_id.to_string());
        }
        opaque_identity(call, principal)
    }
}

impl MediaController for LiveKitService {
    fn capabilities(&self) -> MediaCapabilities {
        MediaCapabilities {
            source_permissions: true,
            deny_receive_media: true,
            mute_microphone_track: true,
            immediate_credential_revocation: false,
        }
    }

    fn prepare(&self, call: Call, effect: CallEffect) -> CallFuture<'_, CallEffect> {
        Box::pin(async move {
            let CallEffect::MuteMicrophoneNow { principal } = effect else {
                return Ok(effect);
            };
            let client = self
                .room_client()
                .map_err(|_| CallError::UnsupportedMediaCapability)?;
            let identity = self.management_identity(&call.id, &principal)?;
            let participant = match client
                .get_participant(&room_name(&call.id)?, &identity)
                .await
            {
                Ok(participant) => Some(participant),
                Err(error) if not_found(&error) => None,
                Err(_) => return Err(CallError::MediaEnforcementPending),
            };
            let participant_sid = participant
                .as_ref()
                .map(|p| p.sid.clone())
                .unwrap_or_default();
            let track_sids = participant
                .into_iter()
                .flat_map(|p| p.tracks)
                .filter(|t| t.source == TrackSource::Microphone as i32)
                .map(|t| t.sid)
                .collect();
            Ok(CallEffect::BoundMicrophoneMute {
                principal,
                participant_sid,
                track_sids,
            })
        })
    }

    fn issue_join_credential(
        &self,
        call: &Call,
        principal: &CallPrincipal,
        effective: EffectivePermissions,
        now_ms: i64,
    ) -> Result<JoinGrant, CallError> {
        if !effective.join {
            return Err(CallError::NotAuthorized);
        }
        let config = self
            .livekit_config()
            .map_err(|_| CallError::UnsupportedMediaCapability)?;
        let allowed_sources = sources(&effective);
        let credential = AccessToken::with_api_key(&config.api_key, &config.api_secret)
            .with_identity(&self.management_identity(&call.id, principal)?)
            .with_ttl(Duration::from_secs(60))
            .with_grants(VideoGrants {
                room: room_name(&call.id)?,
                room_join: true,
                room_admin: false,
                can_update_own_metadata: false,
                can_publish: !allowed_sources.is_empty(),
                can_subscribe: effective.receive_media,
                can_publish_data: effective.publish_data,
                can_publish_sources: allowed_sources
                    .iter()
                    .map(|s| {
                        match s {
                            TrackSource::Microphone => "microphone",
                            TrackSource::Camera => "camera",
                            TrackSource::ScreenShare => "screen_share",
                            TrackSource::ScreenShareAudio => "screen_share_audio",
                            _ => unreachable!("explicitly selected track source"),
                        }
                        .to_string()
                    })
                    .collect(),
                ..Default::default()
            })
            .to_jwt()
            .map_err(|_| CallError::MediaEnforcementPending)?;
        Ok(JoinGrant {
            call: call.id.clone(),
            revision: call.revision,
            media_endpoint: config.client_url.clone(),
            credential,
            expires_at_ms: now_ms
                .checked_add(60_000)
                .ok_or(CallError::InvalidRequest)?,
            permissions: effective,
        })
    }

    fn apply(&self, call: Call, effect: CallEffect, now_ms: i64) -> CallFuture<'_, ()> {
        Box::pin(async move {
            let _guard = self.management_lock.lock().await;
            let client = self
                .room_client()
                .map_err(|_| CallError::UnsupportedMediaCapability)?;
            let room = room_name(&call.id)?;
            let gated_projection = match &effect {
                CallEffect::ReconcileMember { principal } => {
                    needs_credential_gate(&permissions(&call, principal, now_ms))
                }
                _ => false,
            };
            if matches!(effect, CallEffect::ProjectMetadata) {
                if call.terminal() {
                    return Ok(());
                }
                return match self.publish_metadata(&client, &call).await {
                    Ok(()) => Ok(()),
                    Err(_) => Err(CallError::MediaEnforcementPending),
                };
            }
            if matches!(effect, CallEffect::ProvisionRoom) {
                if call.terminal() {
                    return Ok(());
                }
                client
                    .create_room(
                        &room,
                        livekit_api::services::room::CreateRoomOptions::default(),
                    )
                    .await
                    .map_err(|_| CallError::MediaEnforcementPending)?;
                return Ok(());
            }
            if matches!(effect, CallEffect::EndRoom | CallEffect::EnsureEnded { .. }) {
                if !call.terminal() {
                    return Ok(());
                }
                match client.delete_room(&room).await {
                    Ok(()) => {}
                    Err(error) if not_found(&error) => {}
                    Err(_) => return Err(CallError::MediaEnforcementPending),
                }
                // Self-hosted refresh/reconnect credentials have no verified
                // revocation gate. Keep reconciling, even if the room is absent.
                return Err(CallError::MediaEnforcementPending);
            }
            let participants = match client.list_participants(&room).await {
                Ok(participants) => participants,
                Err(error) if not_found(&error) => {
                    return if gated_projection || matches!(effect, CallEffect::EnsureRevoked { .. })
                    {
                        Err(CallError::MediaEnforcementPending)
                    } else {
                        Ok(())
                    };
                }
                Err(_) => return Err(CallError::MediaEnforcementPending),
            };
            if matches!(effect, CallEffect::InspectRoom) {
                for participant in participants {
                    let member = call.members.iter().find(|m| {
                        self.management_identity(&call.id, &m.principal)
                            .is_ok_and(|identity| identity == participant.identity)
                    });
                    let Some(member) = member.filter(|m| call.is_admitted(&m.principal, now_ms))
                    else {
                        match client
                            .remove_participant(&room, &participant.identity)
                            .await
                        {
                            Ok(()) => {}
                            Err(error) if not_found(&error) => {}
                            Err(_) => return Err(CallError::MediaEnforcementPending),
                        }
                        continue;
                    };
                    let effective = permissions(&call, &member.principal, now_ms);
                    stop_denied_tracks(&client, &room, &participant, &effective).await?;
                    let desired = participant_permission(&effective);
                    if participant.permission.as_ref() != Some(&desired) {
                        client
                            .update_participant(
                                &room,
                                &participant.identity,
                                UpdateParticipantOptions {
                                    permission: Some(desired),
                                    ..Default::default()
                                },
                            )
                            .await
                            .map_err(|_| CallError::MediaEnforcementPending)?;
                    }
                }
                return Ok(());
            }
            let principal = match &effect {
                CallEffect::ReconcileMember { principal }
                | CallEffect::RemoveMember { principal }
                | CallEffect::EnsureRevoked { principal, .. }
                | CallEffect::BoundMicrophoneMute { principal, .. } => principal,
                _ => return Err(CallError::UnsupportedMediaCapability),
            };
            let identity = self.management_identity(&call.id, principal)?;
            let authorized = call.lifecycle == CallLifecycle::Active
                && !call.banned(principal)
                && call.member(principal).is_some_and(|m| {
                    m.authorized
                        && m.timeout_until_ms.is_none_or(|t| t <= now_ms)
                        && (call.policy.join_policy != JoinPolicy::Approved || m.approved)
                });
            let Some(participant) = participants.iter().find(|p| p.identity == identity) else {
                return if gated_projection
                    || (!authorized && matches!(effect, CallEffect::EnsureRevoked { .. }))
                {
                    Err(CallError::MediaEnforcementPending)
                } else {
                    Ok(())
                };
            };
            if let CallEffect::BoundMicrophoneMute {
                participant_sid,
                track_sids,
                ..
            } = &effect
            {
                if participant.sid != *participant_sid {
                    return Ok(());
                }
                for track in participant.tracks.iter().filter(|t| {
                    t.source == TrackSource::Microphone as i32 && track_sids.contains(&t.sid)
                }) {
                    client
                        .mute_published_track(&room, &identity, &track.sid, true)
                        .await
                        .map_err(|_| CallError::MediaEnforcementPending)?;
                }
                return Ok(());
            }
            let effective = permissions(&call, principal, now_ms);
            if !authorized {
                match client.remove_participant(&room, &identity).await {
                    Ok(()) => {}
                    Err(error) if not_found(&error) => {}
                    Err(_) => return Err(CallError::MediaEnforcementPending),
                }
                return Err(CallError::MediaEnforcementPending);
            }
            stop_denied_tracks(&client, &room, participant, &effective).await?;
            client
                .update_participant(
                    &room,
                    &identity,
                    UpdateParticipantOptions {
                        permission: Some(participant_permission(&effective)),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|_| CallError::MediaEnforcementPending)?;
            // Permission updates do not invalidate old self-hosted join/refresh
            // credentials. Reconcile denied projections across reconnects and
            // report pending until a deployment supplies a verified admission gate.
            if gated_projection {
                Err(CallError::MediaEnforcementPending)
            } else {
                Ok(())
            }
        })
    }
}

fn not_found(error: &livekit_api::services::ServiceError) -> bool {
    matches!(error, livekit_api::services::ServiceError::Twirp(livekit_api::services::ServerError::Twirp(error))
        if error.code == livekit_api::services::ServerErrorCode::NOT_FOUND)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_source_denial_stops_camera_and_screen_audio_without_touching_microphone() {
        let participant = livekit_protocol::ParticipantInfo {
            tracks: vec![
                livekit_protocol::TrackInfo {
                    sid: "microphone".into(),
                    source: TrackSource::Microphone as i32,
                    ..Default::default()
                },
                livekit_protocol::TrackInfo {
                    sid: "camera".into(),
                    source: TrackSource::Camera as i32,
                    ..Default::default()
                },
                livekit_protocol::TrackInfo {
                    sid: "screen_audio".into(),
                    source: TrackSource::ScreenShareAudio as i32,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let effective = EffectivePermissions {
            publish_microphone: true,
            ..Default::default()
        };
        assert_eq!(
            denied_track_sids(&participant, &effective),
            vec!["camera", "screen_audio"]
        );
    }

    #[test]
    fn source_projection_denies_empty_publication_and_maps_screen_audio_separately() {
        let mut permissions = EffectivePermissions::default();
        let denied = participant_permission(&permissions);
        assert!(!denied.can_publish);
        assert!(denied.can_publish_sources.is_empty());
        permissions.publish_microphone = true;
        permissions.publish_screen_share = true;
        permissions.publish_screen_share_audio = true;
        let granted = participant_permission(&permissions);
        assert_eq!(
            granted.can_publish_sources,
            vec![
                TrackSource::Microphone as i32,
                TrackSource::ScreenShare as i32,
                TrackSource::ScreenShareAudio as i32
            ]
        );
        assert!(!granted.can_subscribe);
        assert!(!granted.can_update_metadata);
    }

    #[test]
    fn scoped_tokens_never_grant_admin_and_guest_identity_cannot_collide_with_owner() {
        let mut call = crate::calls::repository::tests::call();
        call.id.owner_authority =
            CallAuthority::new(format!("omikron-key:{}", "b".repeat(64))).unwrap();
        let service = LiveKitService::new(Some(crate::config::LiveKitConfig {
            hostname: "https://media.invalid".into(),
            client_url: "wss://media.invalid".into(),
            api_key: "test".into(),
            api_secret: "test-secret".into(),
        }));
        service.register_legacy_call(call.id.clone(), call.owner.authority.clone());
        let permissions = EffectivePermissions {
            join: true,
            ..Default::default()
        };
        let grant = service
            .issue_join_credential(
                &call,
                &call.owner,
                permissions,
                SystemCallClock.now_ms().unwrap(),
            )
            .unwrap();
        let claims = livekit_api::access_token::Claims::from_unverified(&grant.credential).unwrap();
        assert!(!claims.video.room_admin);
        assert!(!claims.video.room_create);
        assert!(!claims.video.room_list);
        assert!(!claims.video.can_update_own_metadata);
        assert!(!claims.video.can_publish);
        assert!(!claims.video.can_subscribe);
        assert_eq!(claims.video.room, call.id.id.to_string());
        assert_eq!(claims.sub, call.owner.user_id.to_string());
        let guest = CallPrincipal {
            authority: call.id.owner_authority.clone(),
            user_id: call.owner.user_id,
        };
        let identity = service.management_identity(&call.id, &guest).unwrap();
        assert_ne!(identity, claims.sub);
        assert_eq!(identity.len(), 64);
        assert!(!service.capabilities().immediate_credential_revocation);
    }
}
