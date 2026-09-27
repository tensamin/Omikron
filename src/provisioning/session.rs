use std::{sync::Weak, time::Instant};

use mtp::crypto::PublicKeyBundle;
use uuid::Uuid;

use crate::rho::connection::MtpSender;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisioningMethod {
    Password,
    QrContactCreated,
    QrOwnerCreated,
}

impl ProvisioningMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::QrContactCreated => "qr-contact-created",
            Self::QrOwnerCreated => "qr-owner-created",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisioningRole {
    Contact,
    Owner,
}

impl ProvisioningRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contact => "contact",
            Self::Owner => "owner",
        }
    }
}

#[derive(Clone)]
pub struct ResolvedAccount {
    pub user_id: i64,
    pub username: String,
    pub principal: String,
    pub iota_id: i64,
    pub public_key: PublicKeyBundle,
}

#[derive(Clone)]
pub struct ProvisioningParticipant {
    pub id: u64,
    pub role: ProvisioningRole,
    pub temporary_public_key: PublicKeyBundle,
    pub sender: Weak<MtpSender>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisioningState {
    Created,
    PeerReady,
    AccountBound,
    Authorizing,
    Finishing,
    CredentialDelivered,
}

#[derive(Clone)]
pub struct ProvisioningSession {
    pub id: Uuid,
    pub method: ProvisioningMethod,
    pub contact: Option<ProvisioningParticipant>,
    pub owner: Option<ProvisioningParticipant>,
    pub account: Option<ResolvedAccount>,
    pub state: ProvisioningState,
    pub owner_confirmed: bool,
    pub created_at: Instant,
}

impl ProvisioningSession {
    pub fn require_actor(&self, id: u64, role: ProvisioningRole) -> Result<(), &'static str> {
        let participant = match role {
            ProvisioningRole::Contact => self.contact.as_ref(),
            ProvisioningRole::Owner => self.owner.as_ref(),
        };
        if participant.map(|participant| participant.id) == Some(id) {
            Ok(())
        } else {
            Err("wrong participant")
        }
    }

    pub fn can_deliver(&self) -> Result<(), &'static str> {
        if self.state != ProvisioningState::AccountBound {
            return Err("account is not bound");
        }
        match self.method {
            ProvisioningMethod::Password => Err("password delivery requires Iota authorization"),
            ProvisioningMethod::QrContactCreated
                if self.contact.is_some() && self.owner.is_some() =>
            {
                Ok(())
            }
            ProvisioningMethod::QrOwnerCreated
                if self.contact.is_some() && self.owner.is_some() && self.owner_confirmed =>
            {
                Ok(())
            }
            _ => Err("peer or owner confirmation missing"),
        }
    }
}
