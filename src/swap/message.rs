use crate::swap::role::Role;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Network, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub(crate) enum SwapMessage {
    Proposal(Proposal),
    Offer(Offer),
    OfferResponse(OfferResponse),
    AddressConfirmation(AddressConfirmation),
    PreimageReveal(PreimageReveal),
    KeyReveal(KeyReveal),
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Proposal {
    swap_id: String,
    amount: u64,
    expiration: u64,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Offer {
    swap_id: String,
    initiator_escrow_pubkey: PublicKey,
    participant_escrow_pubkey: PublicKey,
    participant_timelock: u32,
    hashlock: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct OfferResponse {
    swap_id: String,
    initiator_escrow_pubkey: PublicKey,
    participant_escrow_pubkey: PublicKey,
    initiator_timelock: u32,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct AddressConfirmation {
    swap_id: String,
    address: Address,
    role: Role,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct PreimageReveal {
    swap_id: String,
    preimage: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct KeyReveal {
    swap_id: String,
    seckey: SecretKey,
}
