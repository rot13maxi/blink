use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_SHA256};
use bitcoin::blockdata::script;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::serialize::Serialize;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::{Parity, Scalar, Secp256k1, SecretKey};
use bitcoin::util::taproot::{TaprootBuilder, TaprootSpendInfo};
use bitcoin::{Address, KeyPair, Network, Script, XOnlyPublicKey};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::lib::contract::ContractState::{Init, Proposed};

const DEFAULT_TIMELOCK: u16 = 10;

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
pub(crate) struct AcceptProposal {
    id: String,
    maker_pubkey: PublicKey,
    taker_pubkey: PublicKey,
    taker_timelock: u16,
}

#[derive(Deserialize, serde::Serialize)]
pub(crate) struct Accepted {
    id: String,
}

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
    Taker,
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

        let maker_escrow = Escrow {
            mine: privkey.keypair(&secp),
            their_pubkey: None,
            their_privkey: None,
            preimage: Some(preimage.to_hex()),
            hashlock: hashlock.to_hex(),
            timelock: Some(DEFAULT_TIMELOCK),
        };
        let (privkey, _) = secp.generate_keypair(&mut rand::thread_rng());
        let taker_escrow = Escrow {
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
            maker_escrow,
            taker_escrow,
        }
    }

    pub fn propose(&mut self) {
        let proposal: Proposal = self.into();
        self.state = Proposed;
        //TODO: publish on nostr instead of printing
        println!("{}", json!(proposal));
    }

    pub(crate) fn accept_proposal(&mut self, accept_proposal: AcceptProposal) {
        self.maker_escrow.their_pubkey = Some(accept_proposal.maker_pubkey);
        self.taker_escrow.their_pubkey = Some(accept_proposal.taker_pubkey);
        self.taker_escrow.timelock = Some(accept_proposal.taker_timelock);
        self.state = ContractState::Accepted;
    }

    pub(crate) fn accept(&mut self, accept: Accepted) {
        self.state = ContractState::Accepted;
    }

    fn calculate_escrow_pubkey(&self, role: Role) -> (XOnlyPublicKey, Parity) {
        let secp = Secp256k1::new();
        match role {
            Role::Maker => self
                .maker_escrow
                .their_pubkey
                .unwrap()
                .mul_tweak(&secp, &Scalar::from(self.maker_escrow.mine.secret_key()))
                .unwrap()
                .x_only_public_key(),
            Role::Taker => self
                .taker_escrow
                .their_pubkey
                .unwrap()
                .mul_tweak(&secp, &Scalar::from(self.taker_escrow.mine.secret_key()))
                .unwrap()
                .x_only_public_key(),
        }
    }

    fn calculate_escrow_privkey(&self, role: Role) -> SecretKey {
        let secp = Secp256k1::new();
        match role {
            Role::Maker => self
                .maker_escrow
                .their_privkey
                .unwrap()
                .mul_tweak(&Scalar::from(self.maker_escrow.mine.secret_key()))
                .unwrap(),
            Role::Taker => self
                .taker_escrow
                .their_privkey
                .unwrap()
                .mul_tweak(&Scalar::from(self.taker_escrow.mine.secret_key()))
                .unwrap(),
        }
    }

    fn build_taproot_spend_info(&self, role: Role) -> TaprootSpendInfo {
        let secp = Secp256k1::new();
        let (timelock_blocks, hashlock) = match role {
            Role::Maker => (
                self.maker_escrow.timelock.unwrap(),
                self.maker_escrow.hashlock.clone(),
            ),
            Role::Taker => (
                self.taker_escrow.timelock.unwrap(),
                self.taker_escrow.hashlock.clone(),
            ),
        };
        let (timelock_key, hashlock_key) = match role {
            Role::Maker => match self.role {
                Role::Maker => (
                    self.maker_escrow.mine.x_only_public_key().0,
                    self.maker_escrow
                        .their_pubkey
                        .unwrap()
                        .x_only_public_key()
                        .0,
                ),
                Role::Taker => (
                    self.maker_escrow
                        .their_pubkey
                        .unwrap()
                        .x_only_public_key()
                        .0,
                    self.maker_escrow.mine.x_only_public_key().0,
                ),
            },
            Role::Taker => match self.role {
                Role::Maker => (
                    self.taker_escrow
                        .their_pubkey
                        .unwrap()
                        .x_only_public_key()
                        .0,
                    self.taker_escrow.mine.x_only_public_key().0,
                ),
                Role::Taker => (
                    self.taker_escrow.mine.x_only_public_key().0,
                    self.taker_escrow
                        .their_pubkey
                        .unwrap()
                        .x_only_public_key()
                        .0,
                ),
            },
        };
        TaprootBuilder::new()
            .add_leaf(
                1u8,
                build_hashlock_script(hashlock.as_bytes(), &hashlock_key),
            )
            .unwrap()
            .add_leaf(
                1u8,
                build_timelock_script(timelock_blocks as i64, &timelock_key),
            )
            .unwrap()
            .finalize(&secp, self.calculate_escrow_pubkey(role).0)
            .unwrap()
    }

    fn get_address(&self, role: Role) -> Address {
        Address::p2tr_tweaked(
            self.build_taproot_spend_info(role).output_key(),
            self.network,
        )
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
            maker_timelock: value.maker_escrow.timelock.unwrap(),
            amount: Default::default(),
        }
    }
}

impl From<&mut Contract> for AcceptProposal {
    fn from(value: &mut Contract) -> Self {
        AcceptProposal {
            id: value.id.clone(),
            maker_pubkey: value.maker_escrow.mine.public_key().clone(),
            taker_pubkey: value.taker_escrow.mine.public_key().clone(),
            taker_timelock: value.taker_escrow.timelock.unwrap(),
        }
    }
}

impl From<&mut Contract> for Accepted {
    fn from(value: &mut Contract) -> Self {
        Accepted {
            id: value.id.clone()
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

    use crate::lib::contract::{Accepted, AcceptProposal, Contract, ContractState, Proposal, Role};

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

        let accept_proposal = AcceptProposal::from(&mut taker);
        // send that over nostr
        maker.accept_proposal(accept_proposal);
        let accepted_msg = Accepted::from(&mut maker);
        // send that over NOSTR
        taker.accept(accepted_msg);

        // checks
        assert_eq!(maker.state, ContractState::Accepted);
        assert_eq!(taker.state, ContractState::Accepted);
        let maker_generated_maker_address = maker.get_address(Role::Maker);
        let maker_generated_taker_address = maker.get_address(Role::Taker);
        let taker_generated_maker_address = taker.get_address(Role::Maker);
        let taker_generated_taker_address = taker.get_address(Role::Taker);
        assert_eq!(maker.maker_escrow.mine.public_key(), taker.maker_escrow.their_pubkey.unwrap());
        assert_eq!(taker.maker_escrow.mine.public_key(), maker.maker_escrow.their_pubkey.unwrap());
        assert_eq!(maker.calculate_escrow_pubkey(Role::Maker).0, taker.calculate_escrow_pubkey(Role::Maker).0);
        assert_eq!(maker.calculate_escrow_pubkey(Role::Taker).0, taker.calculate_escrow_pubkey(Role::Taker).0);
        assert_eq!(maker.maker_escrow.timelock.unwrap(), taker.maker_escrow.timelock.unwrap());
        assert_eq!(maker.taker_escrow.timelock.unwrap(), taker.taker_escrow.timelock.unwrap());
        assert_eq!(maker_generated_maker_address, taker_generated_maker_address);
        assert_eq!(maker_generated_taker_address, taker_generated_taker_address);
        // end checks


    }
}
