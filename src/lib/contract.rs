use std::borrow::BorrowMut;
use std::mem::take;
use std::ptr::hash;
use bitcoin::{Address, Amount, KeyPair, Network, Script, XOnlyPublicKey};
use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_SHA256};
use bitcoin::blockdata::script;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::hashes::hex::ToHex;
use bitcoin::psbt::serialize::Serialize;
use bitcoin::secp256k1::{Parity, Scalar, Secp256k1, SecretKey};
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::taproot::{TaprootBuilder, TaprootSpendInfo};
use clap::value_parser;
use serde::{Deserialize};
use serde_json::json;
use uuid::Uuid;
use crate::lib::contract::ContractState::{Init, Proposed};

const DEFAULT_TIMELOCK: u16 = 10;

#[derive(Deserialize, serde::Serialize, PartialEq, Debug)]
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
struct Escrow {
    mine: KeyPair,
    their_pubkey: Option<PublicKey>,
    their_privkey: Option<SecretKey>,
    preimage: Option<String>,
    hashlock: String,
    timelock: Option<u16>,
}

#[derive(Deserialize, serde::Serialize)]
struct Proposal {
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
pub struct Contract {
    id: String,
    network: Network,
    state: ContractState,
    role: Role,
    maker_escrow: Escrow,
    taker_escrow: Escrow,
}

impl Contract {

    pub fn new(network: Network) -> Self {
        let secp = Secp256k1::new();
        let (privkey, _) = secp.generate_keypair(&mut rand::thread_rng());
        let preimage = b"MAKE THIS RANDOM";
        let hashlock = sha256::Hash::hash(preimage);

        let my_escrow = Escrow {
            mine: privkey.keypair(&secp),
            their_pubkey: None,
            their_privkey: None,
            preimage: Some(preimage.to_hex()),
            hashlock: hashlock.to_hex(),
            timelock: Some(DEFAULT_TIMELOCK),
        };
        let (privkey, _) = secp.generate_keypair(&mut rand::thread_rng());
        let their_escrow = Escrow {
            mine: privkey.keypair(&secp),
            their_pubkey: None,
            their_privkey: None,
            preimage: Some(preimage.to_hex()),
            hashlock: hashlock.to_hex(),
            timelock: None,
        };

        Self {
            id: Uuid::new_v4().to_string(),
            network,
            state: Init,
            role: Role::Maker,
            maker_escrow: my_escrow,
            taker_escrow: their_escrow,
        }
    }

    pub fn propose(&mut self) {
        let proposal: Proposal = self.into();
        self.state = Proposed;
        //TODO: publish on nostr instead of printing
        println!("{}", json!(proposal));
    }

    fn calculate_escrow_pubkey(&self, role: Role) -> (XOnlyPublicKey, Parity) {
        let secp = Secp256k1::new();
        match role {
            Role::Maker => {
                self.maker_escrow.their_pubkey.unwrap().mul_tweak(&secp, &Scalar::from(self.maker_escrow.mine.secret_key())).unwrap().x_only_public_key()
            }
            Role::Taker => {
                self.taker_escrow.their_pubkey.unwrap().mul_tweak(&secp, &Scalar::from(self.taker_escrow.mine.secret_key())).unwrap().x_only_public_key()
            }
        }
    }

    fn calculate_escrow_privkey(&self, role: Role) -> SecretKey {
        let secp = Secp256k1::new();
        match role {
            Role::Maker => {
                self.maker_escrow.their_privkey.unwrap().mul_tweak( &Scalar::from(self.maker_escrow.mine.secret_key())).unwrap()
            }
            Role::Taker => {
                self.taker_escrow.their_privkey.unwrap().mul_tweak( &Scalar::from(self.taker_escrow.mine.secret_key())).unwrap()
            }
        }
    }

    fn build_taproot_spend_info(&self, role: Role) -> TaprootSpendInfo {
        let secp = Secp256k1::new();
        let (timelock_blocks, hashlock) = match role {
            Role::Maker => (self.maker_escrow.timelock.unwrap(), self.maker_escrow.hashlock.clone()),
            Role::Taker => (self.taker_escrow.timelock.unwrap(), self.taker_escrow.hashlock.clone()),
        };
        let (timelock_key, hashlock_key) = match role {
            Role::Maker => match self.role {
                Role::Maker => (self.maker_escrow.mine.x_only_public_key().0, self.maker_escrow.their_pubkey.unwrap().x_only_public_key().0),
                Role::Taker => (self.maker_escrow.their_pubkey.unwrap().x_only_public_key().0, self.maker_escrow.mine.x_only_public_key().0),
            },
            Role::Taker => match self.role {
                Role::Maker => (self.taker_escrow.their_pubkey.unwrap().x_only_public_key().0, self.taker_escrow.mine.x_only_public_key().0),
                Role::Taker => (self.taker_escrow.mine.x_only_public_key().0, self.taker_escrow.their_pubkey.unwrap().x_only_public_key().0),
            }
        };
        TaprootBuilder::new()
            .add_leaf(1u8, build_hashlock_script(hashlock.as_bytes(), &hashlock_key))
            .unwrap()
            .add_leaf(1u8, build_timelock_script(timelock_blocks as i64, &timelock_key))
            .unwrap()
            .finalize(&secp, self.calculate_escrow_pubkey(role).0)
            .unwrap()
    }

    fn get_address(&self, role: Role) -> Address {
        Address::p2tr_tweaked(self.build_taproot_spend_info(role).output_key(), self.network)
    }

}

impl From<&mut Contract> for Proposal {
    fn from(value: &mut Contract) -> Proposal {
        Proposal {
            id: value.id.clone(),
            network: value.network,
            maker_pubkey: value.maker_escrow.mine.public_key().clone(),
            taker_pubkey: value.taker_escrow.mine.public_key().clone(),
            hashlock: value.maker_escrow.hashlock.clone(),
            maker_timelock: 0,
            amount: Default::default(),
        }
    }
}

impl From<Proposal> for Contract {
    fn from(value: Proposal) -> Self {
        let secp = Secp256k1::new();
        let (privkey, _) = secp.generate_keypair(&mut rand::thread_rng());
        let maker_escrow = Escrow {
            mine: privkey.keypair(&secp),
            their_pubkey: Some(value.maker_pubkey),
            their_privkey: None,
            preimage: None,
            hashlock: value.hashlock.clone(),
            timelock: Some(value.maker_timelock),
        };

        let (privkey, _) = secp.generate_keypair(&mut rand::thread_rng());
        let taker_escrow = Escrow {
            mine: privkey.keypair(&secp),
            their_pubkey: Some(value.taker_pubkey),
            their_privkey: None,
            preimage: None,
            hashlock: value.hashlock,
            timelock: Some(value.maker_timelock + 10),
        };

        Contract {
            id: value.id,
            network: value.network,
            state: ContractState::Proposed,
            role: Role::Taker,
            maker_escrow,
            taker_escrow,
        }
    }
}

fn build_timelock_script(nblocks: i64, pubkey: &XOnlyPublicKey) -> Script {
    script::Builder::new()
        .push_int(nblocks)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn build_hashlock_script(hash: &[u8], pubkey: &XOnlyPublicKey) -> Script {
    script::Builder::new()
        .push_opcode(OP_SHA256)
        .push_slice(hash)
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}


#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use crate::lib::contract::{Contract, ContractState, Proposal};

    #[test]
    fn test_contract_construction() {
        let network = Network::Regtest;
        let mut maker = Contract::new(network);
        let proposal = Proposal::from(&mut maker);
        maker.propose();
        // now we'd serialize it and send it over nostr
        let mut taker = Contract::from(proposal);
        assert_eq!(maker.state, ContractState::Proposed);
        assert_eq!(taker.state, ContractState::Proposed);
    }
}