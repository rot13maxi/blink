use bitcoin::secp256k1::SecretKey;
use bitcoin::{Network, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, serde::Serialize)]
pub(crate) struct Proposal {
    id: String,
    network: Network,
    maker_pubkey: PublicKey,
    taker_pubkey: PublicKey,
    hashlock: String,
    maker_timelock: u16,
    amount: u64,
    // TODO: contract expiry?
}

#[derive(Deserialize, serde::Serialize)]
pub(crate) struct Offer {
    id: String,
    maker_pubkey: PublicKey,
    taker_pubkey: PublicKey,
    taker_timelock: u16,
}

#[derive(Deserialize, serde::Serialize)]
pub(crate) struct FinalizeDeal {
    id: String,
}

#[derive(Deserialize, serde::Serialize)]
pub(crate) struct PreimageReveal {
    id: String,
    preimage: String,
}

#[derive(Deserialize, serde::Serialize)]
pub(crate) struct KeyReveal {
    id: String,
    maker_escrow_seckey: SecretKey,
    taker_escrow_seckey: SecretKey,
}
