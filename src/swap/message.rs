use crate::swap::role::Role;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{Address, Network};
use serde::{Deserialize, Serialize};
use crate::swap::swap::Swap;

/// Messages that are broadcast publicly
#[derive(Deserialize, Serialize, Debug)]
pub(crate) enum SwapAnnoucement {
    Proposal(Proposal),
    Closed(String), // swap_id
}

/// Messages that are exchanged between parties in a swap
#[derive(Deserialize, Serialize, Debug)]
pub(crate) enum SwapMessage {
    Offer(Offer),
    OfferResponse(OfferResponse),
    AddressConfirmation(AddressConfirmation),
    PreimageReveal(PreimageReveal),
    KeyReveal(KeyReveal),
    Cancel(Cancel),
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct Proposal {
    swap_id: String,
    amount: u64,
    expiration: u64,
}

impl From<&Swap> for Proposal {
    fn from(value: &Swap) -> Self {
        Proposal {
            swap_id: value.swap_id.clone(),
            amount: value.amount,
            expiration: 0, //todo: let expiration be configurable
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub(crate) struct Offer {
    pub(crate) swap_id: String,
    pub(crate) initiator_escrow_pubkey: PublicKey,
    pub(crate) participant_escrow_pubkey: PublicKey,
    pub(crate) participant_timelock: u16,
    pub(crate) hashlock: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct OfferResponse {
    pub(crate) swap_id: String,
    pub(crate) initiator_escrow_pubkey: PublicKey,
    pub(crate) participant_escrow_pubkey: PublicKey,
    pub(crate) initiator_timelock: u32,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct AddressConfirmation {
    swap_id: String,
    address: Address,
    role: Role,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct PreimageReveal {
    swap_id: String,
    preimage: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct KeyReveal {
    swap_id: String,
    seckey: SecretKey,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct Cancel {
    pub(crate) swap_id: String,
}