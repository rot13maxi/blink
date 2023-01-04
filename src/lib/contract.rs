use std::borrow::BorrowMut;
use std::ptr::hash;
use bitcoin::{Amount, KeyPair, PrivateKey, XOnlyPublicKey};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::hashes::hex::ToHex;
use bitcoin::psbt::serialize::Serialize;
use bitcoin::secp256k1::Secp256k1;
use clap::value_parser;
use serde::{Deserialize};
use serde_json::json;
use uuid::Uuid;
use crate::lib::contract::ContractState::{Init, Proposed};

const DEFAULT_TIMELOCK: u16 = 10;

#[derive(Deserialize, serde::Serialize)]
enum ContractState {
    Init,
    Offered,
    Proposed,
    Accepted,
    Cancelled,
    Locked,
    HashRevealed,
    KeyRevealed,
    TimedOut,
    Closed,
}

#[derive(Deserialize, serde::Serialize)]
enum Role {
    Maker,
    Taker
}

#[derive(Deserialize, serde::Serialize)]
struct EscrowKeys {
    mine: KeyPair,
    their_pubkey: Option<XOnlyPublicKey>,
    their_privkey: Option<PrivateKey>,
}

#[derive(Deserialize, serde::Serialize)]
struct Proposal {
    id: String,
    maker_pubkey: XOnlyPublicKey,
    taker_pubkey: XOnlyPublicKey,
    hashlock: String,
    maker_timelock: u16,
    amount: u64,
    // TODO: contract expiry?
}

#[derive(Deserialize, serde::Serialize)]
pub struct Contract {
    id: String,
    state: ContractState,
    role: Role,
    my_escrow: EscrowKeys,
    their_escrow: EscrowKeys,
    preimage: Option<String>,
    hashlock: Option<String>,
    my_timelock: u16,
    counterparty_timelock: Option<u16>,
}

impl Contract {
    pub fn new_offer() -> Self {
        Self::new(Role::Maker)
    }

    fn new(role: Role) -> Self {
        let secp = Secp256k1::new();
        let (privkey, _) = secp.generate_keypair(&mut rand::thread_rng());
        let my_escrow = EscrowKeys {
            mine: privkey.keypair(&secp),
            their_pubkey: None,
            their_privkey: None,
        };
        let (privkey, _) = secp.generate_keypair(&mut rand::thread_rng());
        let their_escrow = EscrowKeys {
            mine: privkey.keypair(&secp),
            their_pubkey: None,
            their_privkey: None,
        };
        let (preimage, hashlock) = match role {
            Role::Maker => {
                let preimage = b"MAKE THIS RANDOM";
                let hashlock = sha256::Hash::hash(preimage);
                (Some(preimage.to_hex()), Some(hashlock.to_hex()))
            }
            Role::Taker => {(None, None)}
        };

        Self {
            id: Uuid::new_v4().to_string(),
            state: Init,
            role,
            my_escrow,
            their_escrow,
            preimage,
            hashlock,
            my_timelock: DEFAULT_TIMELOCK,
            counterparty_timelock: None,
        }
    }

    pub fn propose(&mut self) {
        let proposal: Proposal = self.into();
        self.state = Proposed;
        //TODO: publish on nostr instead of printing
        println!("{}", json!(proposal));
    }
}

impl From<&mut Contract> for Proposal {
    fn from(value: &mut Contract) -> Proposal {
        Proposal {
            id: value.id.clone(),
            maker_pubkey: value.my_escrow.mine.x_only_public_key().0.clone(),
            taker_pubkey: value.their_escrow.mine.x_only_public_key().0.clone(),
            hashlock: value.hashlock.as_ref().expect("hashlock required").clone(),
            maker_timelock: 0,
            amount: Default::default(),
        }
    }
}