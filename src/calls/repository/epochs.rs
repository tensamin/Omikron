use super::*;
use serde::Deserialize;

// The pinned wrapping protocol and Iota directory cap ciphertext retention at three days.
const MAX_ENVELOPE_TTL_MS: i64 = 3 * 24 * 60 * 60 * 1000;

#[derive(Clone, Debug)]
pub struct PendingEpochEnvelope {
    pub call: CallId,
    pub recipient: CallPrincipal,
    pub epoch: u64,
    pub generation: u64,
    pub payload: Vec<u8>,
    pub staged: bool,
    pub activated: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stage {
    operation_id: Uuid,
    call_id: CallId,
    recipient: CallPrincipal,
    epoch: u64,
    created_at_ms: i64,
    expires_at_ms: i64,
    secret_id: String,
    wrapping_scheme: String,
    encrypted_secret: Vec<u8>,
    kem_ciphertext: Vec<u8>,
}

impl SqliteCallRepository {
    pub async fn stage_epoch_envelope(
        &self,
        id: CallId,
        actor: AuthenticatedCallActor,
        payload: Vec<u8>,
    ) -> Result<(), CallError> {
        let budget = self.max_commands_per_minute;
        let max_pending = self.max_pending_key_epochs;
        if payload.len() > 16 * 1024 {
            return Err(CallError::InvalidRequest);
        }
        let stage: Stage =
            serde_json::from_slice(&payload).map_err(|_| CallError::InvalidRequest)?;
        if stage.call_id != id
            || stage.operation_id.is_nil()
            || stage.recipient.user_id == 0
            || stage.created_at_ms < 0
            || stage.secret_id.is_empty()
            || stage.secret_id.len() > 256
            || stage.encrypted_secret.is_empty()
            || stage.encrypted_secret.len() > 1024
            || stage.kem_ciphertext.is_empty()
            || stage.kem_ciphertext.len() > 4096
            || stage.wrapping_scheme != "mtp-call-secret-kem-chacha20poly1305-hkdf-sha256-v1"
        {
            return Err(CallError::InvalidRequest);
        }
        self.blocking(move |db| {
            let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let actor_json=json(actor.principal())?;
            let existing:Option<Vec<u8>>=tx.query_row("SELECT payload FROM managed_call_key_operations WHERE authority=?1 AND call_id=?2 AND actor=?3 AND operation_id=?4",
                params![id.owner_authority.as_str(),id.id.to_string(),actor_json,stage.operation_id.to_string()],|row|row.get(0)).optional().map_err(storage)?;
            if let Some(existing)=existing { return if existing==payload { Ok(()) } else { Err(CallError::OperationConflict) }; }
            let call=Self::read_from(&tx,&id)?;
            let now_ms=SystemCallClock.now_ms()?;
            call.authorize_key_proposal(&actor,stage.epoch,now_ms)?;
            if stage.epoch<=call.key_epoch || stage.expires_at_ms<=now_ms || stage.expires_at_ms>now_ms.saturating_add(call.policy.invite_ttl_ms)
                || stage.created_at_ms>now_ms.saturating_add(60_000) || stage.expires_at_ms<=stage.created_at_ms
                || stage.expires_at_ms.saturating_sub(stage.created_at_ms)>MAX_ENVELOPE_TTL_MS { return Err(CallError::KeyEpochPending); }
            let epoch=i64::try_from(stage.epoch).map_err(storage)?;
            let generation=i64::try_from(call.rotation_generation).map_err(storage)?;
            let expected=call.key_recipients(now_ms);
            if !expected.contains(&stage.recipient) { return Err(CallError::NotAuthorized); }
            Self::consume_write_budget(&tx,&id,actor.principal(),now_ms,budget)?;
            tx.execute("UPDATE managed_call_key_plans SET available=-1 WHERE authority=?1 AND call_id=?2 AND available=0 AND (generation!=?3 OR recipients_json!=?4 OR EXISTS(SELECT 1 FROM managed_call_key_envelopes e WHERE e.authority=managed_call_key_plans.authority AND e.call_id=managed_call_key_plans.call_id AND e.epoch=managed_call_key_plans.epoch AND json_extract(CAST(e.payload AS TEXT),'$.expires_at_ms')<=?5))",
                params![id.owner_authority.as_str(),id.id.to_string(),generation,json(&expected)?,now_ms]).map_err(storage)?;
            let plan:Option<(i64,String,String,i64)>=tx.query_row("SELECT generation,proposer,recipients_json,available FROM managed_call_key_plans WHERE authority=?1 AND call_id=?2 AND epoch=?3",
                params![id.owner_authority.as_str(),id.id.to_string(),epoch],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional().map_err(storage)?;
            if let Some((stored_generation,proposer,members,available))=plan {
                if stored_generation!=generation || proposer!=actor_json || members!=json(&expected)? || available<0 { return Err(CallError::KeyEpochPending); }
            } else {
                let pending:i64=tx.query_row("SELECT COUNT(*) FROM managed_call_key_plans WHERE authority=?1 AND call_id=?2 AND generation=?3 AND recipients_json=?4 AND available=0",
                    params![id.owner_authority.as_str(),id.id.to_string(),generation,json(&expected)?],|row|row.get(0)).map_err(storage)?;
                if pending>=max_pending as i64 { return Err(CallError::RateLimited); }
                let largest:Option<i64>=tx.query_row("SELECT MAX(epoch) FROM managed_call_key_plans WHERE authority=?1 AND call_id=?2",
                    params![id.owner_authority.as_str(),id.id.to_string()],|row|row.get(0)).map_err(storage)?;
                if largest.is_some_and(|largest|epoch<=largest) { return Err(CallError::KeyEpochPending); }
                tx.execute("INSERT INTO managed_call_key_plans(authority,call_id,epoch,generation,proposer,recipients_json) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![id.owner_authority.as_str(),id.id.to_string(),epoch,generation,actor_json,json(&expected)?]).map_err(storage)?;
            }
            let stored:Option<Vec<u8>>=tx.query_row("SELECT payload FROM managed_call_key_envelopes WHERE authority=?1 AND call_id=?2 AND epoch=?3 AND recipient=?4",
                params![id.owner_authority.as_str(),id.id.to_string(),epoch,json(&stage.recipient)?],|row|row.get(0)).optional().map_err(storage)?;
            if let Some(stored)=stored {
                // A changed operation ID does not permit changed ciphertext.
                let existing:Stage=serde_json::from_slice(&stored).map_err(storage)?;
                if existing.encrypted_secret!=stage.encrypted_secret || existing.kem_ciphertext!=stage.kem_ciphertext
                    || existing.secret_id!=stage.secret_id || existing.wrapping_scheme!=stage.wrapping_scheme
                    || existing.expires_at_ms!=stage.expires_at_ms || existing.created_at_ms!=stage.created_at_ms { return Err(CallError::EnvelopeConflict); }
            } else {
                tx.execute("INSERT INTO managed_call_key_envelopes(authority,call_id,epoch,recipient,generation,payload) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![id.owner_authority.as_str(),id.id.to_string(),epoch,json(&stage.recipient)?,generation,payload]).map_err(storage)?;
            }
            tx.execute("INSERT INTO managed_call_key_operations(authority,call_id,actor,operation_id,payload) VALUES(?1,?2,?3,?4,?5)",
                params![id.owner_authority.as_str(),id.id.to_string(),actor_json,stage.operation_id.to_string(),payload]).map_err(storage)?;
            tx.commit().map_err(storage)
        }).await
    }

    pub async fn pending_epoch_envelopes(&self) -> Result<Vec<PendingEpochEnvelope>, CallError> {
        self.blocking(|db| {
            let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let now_ms=SystemCallClock.now_ms()?;
            let mut pending=Vec::new();
            {
            let mut stmt=tx.prepare("SELECT e.authority,e.call_id,e.recipient,e.epoch,e.generation,e.payload,e.staged,e.activated FROM managed_call_key_envelopes e JOIN managed_calls c ON c.authority=e.authority AND c.call_id=e.call_id JOIN managed_call_key_plans p ON p.authority=e.authority AND p.call_id=e.call_id AND p.epoch=e.epoch WHERE p.available=0 AND e.activated=0 AND e.next_attempt_ms<=?1 AND e.generation=json_extract(c.state_json,'$.rotation_generation') AND e.epoch>json_extract(c.state_json,'$.key_epoch') AND json_extract(c.state_json,'$.lifecycle')='active' AND json_extract(CAST(e.payload AS TEXT),'$.expires_at_ms')>?1 ORDER BY e.next_attempt_ms,e.epoch,e.authority,e.call_id,e.recipient LIMIT 4").map_err(storage)?;
            let rows=stmt.query_map([now_ms],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,u64>(3)?,row.get::<_,u64>(4)?,row.get::<_,Vec<u8>>(5)?,row.get::<_,bool>(6)?,row.get::<_,bool>(7)?))).map_err(storage)?;
            for row in rows {
                let (authority,call_id,recipient,epoch,generation,payload,staged,activated)=row.map_err(storage)?;
                let call=CallId { owner_authority:CallAuthority::new(authority)?,id:Uuid::parse_str(&call_id).map_err(storage)? };
                let current=Self::read_from(&tx,&call)?;
                if current.terminal() || current.rotation_generation!=generation || epoch<=current.key_epoch { continue; }
                pending.push(PendingEpochEnvelope { call,recipient:serde_json::from_str(&recipient).map_err(storage)?,epoch,generation,payload,staged,activated });
            }
            }
            // Reserve only the worker's bounded batch. Failed/offline recipients
            // move behind untouched work, including batches beyond the old 128-row page.
            for item in &pending {
                tx.execute("UPDATE managed_call_key_envelopes SET next_attempt_ms=?5 WHERE authority=?1 AND call_id=?2 AND recipient=?3 AND epoch=?4",
                    params![item.call.owner_authority.as_str(),item.call.id.to_string(),json(&item.recipient)?,i64::try_from(item.epoch).map_err(storage)?,now_ms.saturating_add(60_000)]).map_err(storage)?;
            }
            tx.commit().map_err(storage)?;
            Ok(pending)
        }).await
    }

    pub async fn epoch_envelope_staged(
        &self,
        id: CallId,
        recipient: CallPrincipal,
        epoch: u64,
        generation: u64,
    ) -> Result<(), CallError> {
        self.epoch_receipt(id, recipient, epoch, generation, false)
            .await
    }

    pub async fn epoch_envelope_activated(
        &self,
        id: CallId,
        recipient: CallPrincipal,
        epoch: u64,
        generation: u64,
    ) -> Result<(), CallError> {
        self.epoch_receipt(id, recipient, epoch, generation, true)
            .await
    }

    async fn epoch_receipt(
        &self,
        id: CallId,
        recipient: CallPrincipal,
        epoch: u64,
        generation: u64,
        activate: bool,
    ) -> Result<(), CallError> {
        self.blocking(move |db| {
            let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let call=Self::read_from(&tx,&id)?;
            if call.terminal() || call.rotation_generation!=generation || call.banned(&recipient) || !call.key_recipients(SystemCallClock.now_ms()?).contains(&recipient) { return Err(CallError::KeyEpochPending); }
            let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM managed_call_key_plans WHERE authority=?1 AND call_id=?2 AND epoch=?3 AND available>=0)",
                params![id.owner_authority.as_str(),id.id.to_string(),i64::try_from(epoch).map_err(storage)?],|row|row.get(0)).map_err(storage)?;
            if !active {return Err(CallError::KeyEpochPending);}
            let now_ms=SystemCallClock.now_ms()?;
            let changed=tx.execute(if activate {
                "UPDATE managed_call_key_envelopes SET activated=1 WHERE authority=?1 AND call_id=?2 AND epoch=?3 AND recipient=?4 AND generation=?5 AND staged=1 AND json_extract(CAST(payload AS TEXT),'$.expires_at_ms')>?6"
            } else {
                "UPDATE managed_call_key_envelopes SET staged=1 WHERE authority=?1 AND call_id=?2 AND epoch=?3 AND recipient=?4 AND generation=?5 AND json_extract(CAST(payload AS TEXT),'$.expires_at_ms')>?6"
            },params![id.owner_authority.as_str(),id.id.to_string(),i64::try_from(epoch).map_err(storage)?,json(&recipient)?,i64::try_from(generation).map_err(storage)?,now_ms]).map_err(storage)?;
            if changed!=1 { return Err(CallError::KeyEpochPending); }
            tx.commit().map_err(storage)
        }).await
    }

    pub async fn commit_epoch(
        &self,
        id: CallId,
        actor: AuthenticatedCallActor,
        epoch: u64,
        generation: u64,
    ) -> Result<(), CallError> {
        self.blocking(move |db| {
            let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let mut call=Self::read_from(&tx,&id)?;
            let now_ms=SystemCallClock.now_ms()?;
            if !call.is_admitted(actor.principal(),now_ms) || call.member(actor.principal()).is_some_and(|m|m.guest) { return Err(CallError::NotAuthorized); }
            if call.rotation_generation!=generation { return Err(CallError::KeyEpochPending); }
            if call.key_epoch==epoch && call.key_available_generation==generation { return Ok(()); }
            if epoch<=call.key_epoch { return Err(CallError::KeyEpochPending); }
            let (stored_generation,proposer,expected,available):(u64,String,String,i64)=tx.query_row("SELECT generation,proposer,recipients_json,available FROM managed_call_key_plans WHERE authority=?1 AND call_id=?2 AND epoch=?3",
                params![id.owner_authority.as_str(),id.id.to_string(),i64::try_from(epoch).map_err(storage)?],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional().map_err(storage)?.ok_or(CallError::KeyEpochPending)?;
            if available<0 {return Err(CallError::KeyEpochPending);}
            if stored_generation!=generation || (proposer!=json(actor.principal())? && actor.principal()!=&call.owner) { return Err(CallError::NotAuthorized); }
            let expected:Vec<CallPrincipal>=serde_json::from_str(&expected).map_err(storage)?;
            if expected!=call.key_recipients(now_ms) { return Err(CallError::KeyEpochPending); }
            for recipient in &expected {
                let ready:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM managed_call_key_envelopes WHERE authority=?1 AND call_id=?2 AND epoch=?3 AND recipient=?4 AND generation=?5 AND staged=1 AND activated=1 AND json_extract(CAST(payload AS TEXT),'$.expires_at_ms')>?6)",
                    params![id.owner_authority.as_str(),id.id.to_string(),i64::try_from(epoch).map_err(storage)?,json(recipient)?,i64::try_from(generation).map_err(storage)?,now_ms],|row|row.get(0)).map_err(storage)?;
                if !ready { return Err(CallError::KeyEpochPending); }
            }
            call.key_epoch=epoch;
            call.key_available_generation=generation;
            call.key_installations.clear();
            call.rotation_required=true;
            for invitation in &mut call.invitations {
                if expected.contains(&invitation.recipient) { invitation.delivery_ready=true; }
            }
            Self::host_transition(&tx,&mut call,None,CallEventKind::KeyEpochAvailable,now_ms)?;
            tx.execute("UPDATE managed_call_key_plans SET available=1 WHERE authority=?1 AND call_id=?2 AND epoch=?3",
                params![id.owner_authority.as_str(),id.id.to_string(),i64::try_from(epoch).map_err(storage)?]).map_err(storage)?;
            tx.commit().map_err(storage)
        }).await
    }

    pub async fn epoch_numbers(
        &self,
        id: CallId,
        recipient: CallPrincipal,
    ) -> Result<Vec<u64>, CallError> {
        self.blocking(move |db| {
            let mut stmt=db.prepare("SELECT epoch FROM managed_call_key_envelopes WHERE authority=?1 AND call_id=?2 AND recipient=?3 UNION SELECT epoch FROM managed_call_legacy_envelopes WHERE authority=?1 AND call_id=?2 AND recipient=?3 ORDER BY epoch").map_err(storage)?;
            let rows=stmt.query_map(params![id.owner_authority.as_str(),id.id.to_string(),json(&recipient)?],|row|row.get::<_,u64>(0)).map_err(storage)?;
            let mut epochs=rows.collect::<Result<Vec<_>,_>>().map_err(storage)?;
            // Imported legacy epoch zero can predate the durable owner saga.
            if !epochs.contains(&0) { epochs.insert(0,0); }
            Ok(epochs)
        }).await
    }

    pub async fn epoch_payload(
        &self,
        id: CallId,
        recipient: CallPrincipal,
        epoch: u64,
    ) -> Result<Option<Vec<u8>>, CallError> {
        self.blocking(move |db| {
            let call=Self::read_from(db,&id)?;
            let now_ms=SystemCallClock.now_ms()?;
            call.authorize_envelope_read(&recipient,epoch,now_ms)?;
            db.query_row("SELECT payload FROM managed_call_key_envelopes WHERE authority=?1 AND call_id=?2 AND recipient=?3 AND epoch=?4 AND activated=1 AND json_extract(CAST(payload AS TEXT),'$.expires_at_ms')>?5",
                params![id.owner_authority.as_str(),id.id.to_string(),json(&recipient)?,i64::try_from(epoch).map_err(storage)?,now_ms],|row|row.get(0)).optional().map_err(storage)
        }).await
    }
}
