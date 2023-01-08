use std::collections::HashMap;
use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_SHA256};
use bitcoin::blockdata::script;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::serialize::Serialize;
use bitcoin::psbt::Prevouts;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::{Parity, Scalar, Secp256k1, SecretKey};
use bitcoin::util::sighash::SighashCache;
use bitcoin::util::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    schnorr, secp256k1, Address, KeyPair, Network, OutPoint, PackedLockTime,
    SchnorrSighashType, Script, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use serde::Deserialize;
use serde_json::json;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use uuid::Uuid;
use crate::swap::components::{EscrowKeys, Hashlock, Timelock};
use crate::swap::role::Role;

use crate::swap::utxo::Utxo;

const DEFAULT_TIMELOCK: u16 = 144;
const REQUIRED_CONFIRMATIONS: u32 = 1;


#[derive(PartialEq, Debug)]
enum SpendPath {
    Unspendable,
    Timelock,
    Hashlock,
    Keypath,
}

#[derive(Deserialize, serde::Serialize, Debug)]
pub struct Contract {
    contract_id: String,
    escrow_keys: HashMap<Role, EscrowKeys>,
    hashlock: Hashlock,
    timelock: Timelock,
    utxo: Option<Utxo>,
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
            contract_id: Uuid::new_v4().to_string(),
            network,
            state: Init,
            role: Role::Maker,
            maker_escrow,
            taker_escrow,
        }
    }

    pub fn id(&self) -> String {
        format!("{}::{}", self.contract_id, self.role)
    }

    pub fn propose(&mut self) {
        let proposal: Proposal = self.into();
        self.state = Proposed;
        //TODO: publish on nostr instead of printing
        println!("{}", json!(proposal));
    }

    pub(crate) fn accept_offer(&mut self, offer: Offer) {
        self.maker_escrow.their_pubkey = Some(offer.maker_pubkey);
        self.taker_escrow.their_pubkey = Some(offer.taker_pubkey);
        self.taker_escrow.timelock = Some(offer.taker_timelock);
        self.state = ContractState::Accepted;
    }

    pub(crate) fn finalize_deal(&mut self, _finalized_deal: FinalizeDeal) {
        // todo: make this return a Result so I'm not panicing
        // todo: check that this is for the right ID
        // assert_eq!(finalized_deal.id, self.id());
        self.state = ContractState::Accepted;
    }

    pub(crate) fn reveal_preimage(&mut self) -> Result<PreimageReveal, ()> {
        let preimage = self.maker_escrow.preimage.as_ref().ok_or(())?;
        self.state = ContractState::HashRevealed;
        Ok(PreimageReveal {
            id: self.contract_id.clone(),
            preimage: preimage.to_string()
        })
    }

    pub(crate) fn accept_preimage(&mut self, preimage_reveal: PreimageReveal) {
        // todo: check that the ID is kosher
        self.maker_escrow.preimage = Some(preimage_reveal.preimage.clone());
        self.taker_escrow.preimage = Some(preimage_reveal.preimage.clone());
        self.state = ContractState::HashRevealed;
    }

    pub(crate) fn reveal_seckey(&mut self) -> Result<KeyReveal, ()> {
        self.state = ContractState::KeyRevealed;
        Ok(KeyReveal {
            id: self.contract_id.clone(),
            maker_escrow_seckey: self.maker_escrow.mine.secret_key().clone(),
            taker_escrow_seckey: self.taker_escrow.mine.secret_key().clone(),
        })
    }

    pub(crate) fn accept_seckey(&mut self, key_reveal: KeyReveal) {
        // todo: validate id
        self.maker_escrow.their_privkey = Some(key_reveal.maker_escrow_seckey);
        self.taker_escrow.their_privkey = Some(key_reveal.taker_escrow_seckey);
    }

    fn calculate_escrow_pubkey(&self, role: Role) -> (XOnlyPublicKey, Parity) {
        let secp = Secp256k1::new();
        let escrow = match role {
            Role::Maker => &self.maker_escrow,
            Role::Taker => &self.taker_escrow
        };
        escrow.their_pubkey.unwrap().mul_tweak(&secp, &Scalar::from(escrow.mine.secret_key())).unwrap().x_only_public_key()
    }


    fn calculate_escrow_privkey(&self, escrow: &Escrow) -> SecretKey {
        escrow.their_privkey.unwrap().mul_tweak(&Scalar::from(escrow.mine.secret_key())).unwrap()
    }

    fn build_taproot_spend_info(&self, role: Role) -> TaprootSpendInfo {
        let secp = Secp256k1::new();

        let escrow = match role {
            Role::Maker => &self.maker_escrow,
            Role::Taker => &self.taker_escrow,
        };

        let timelock_blocks = escrow.timelock.unwrap();
        let hashlock = escrow.hashlock.clone();
        let (timelock_key, hashlock_key) = if role == self.role {
            (escrow.mine.x_only_public_key().0, escrow.their_pubkey.unwrap().x_only_public_key().0)
        } else {
            (escrow.their_pubkey.unwrap().x_only_public_key().0, escrow.mine.x_only_public_key().0)
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

    pub(crate) fn get_address(&self, role: Role) -> Address {
        Address::p2tr_tweaked(
            self.build_taproot_spend_info(role).output_key(),
            self.network,
        )
    }

    fn get_spend_path(&self, confirmations: u32) -> SpendPath {
        if confirmations < REQUIRED_CONFIRMATIONS {
            return SpendPath::Unspendable;
        }
        // their escrow for hashlock and keyspend paths, my escrow for timelock
        let escrow = match self.role {
            Role::Maker => &self.maker_escrow,
            Role::Taker => &self.taker_escrow,
        };
        if escrow.their_privkey.is_some() {
            return SpendPath::Keypath;
        }
        if escrow.preimage.is_some() {
            return SpendPath::Hashlock;
        }
        let escrow = match self.role {
            Role::Maker => &self.taker_escrow,
            Role::Taker => &self.maker_escrow,
        };
        if let Some(timelock) = escrow.timelock {
            if timelock <= confirmations as u16 {
                return SpendPath::Timelock;
            }
        }
        SpendPath::Unspendable
    }

    /// Get a signed, ready-to-send TX that spends the contract
    pub fn get_spending_tx(
        &self,
        utxo: &Utxo,
        address: Address,
        fee_rate: Option<u64>,
    ) -> Result<Transaction, ()> {
        let spend_path = self.get_spend_path(utxo.confirmations);
        // my escrow for timelock, their escrow otherwise
        let escrow = if spend_path == SpendPath::Timelock {
            match self.role {
                Role::Maker => &self.maker_escrow,
                Role::Taker => &self.taker_escrow,
            }
        } else {
            match self.role {
                Role::Maker => &self.taker_escrow,
                Role::Taker => &self.maker_escrow,
            }
        };
        let prev_outpoint = OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        };
        let prev_txout = TxOut {
            value: utxo.amount.to_sat(),
            script_pubkey: utxo.script_pub_key.clone(),
        };
        let vbytes = 600; // totally just made up number. todo: calculate this
        let fee = vbytes * fee_rate.unwrap_or(1);
        let mut tx = Transaction {
            version: 2,
            lock_time: PackedLockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev_outpoint,
                sequence: if spend_path == SpendPath::Timelock {
                    Sequence::from_height(escrow.timelock.unwrap())
                } else {
                    Sequence::MAX
                },
                script_sig: script::Builder::new().into_script(),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: utxo.amount.to_sat() - fee,
                script_pubkey: address.script_pubkey(),
            }],
        };
        let prevout = vec![prev_txout];
        let secp = Secp256k1::new();
        let mut sighash_cache = SighashCache::new(&tx);
        // build and push tx witness based on what kind of tx we're doing
        match spend_path {
            SpendPath::Unspendable => return Err(()),
            SpendPath::Timelock => {
                let timelock_script = build_timelock_script(
                    escrow.timelock.unwrap() as i64,
                    &escrow.mine.x_only_public_key().0,
                );
                let control_block = self
                    .build_taproot_spend_info(self.role.clone())
                    .control_block(&(timelock_script.clone(), LeafVersion::TapScript))
                    .unwrap();
                let sighash = sighash_cache
                    .taproot_script_spend_signature_hash(
                        0,
                        &Prevouts::All(&prevout),
                        TapLeafHash::from_script(&timelock_script, LeafVersion::TapScript),
                        SchnorrSighashType::Default,
                    )
                    .unwrap();
                let message = secp256k1::Message::from(sighash);
                let signature = secp.sign_schnorr(&message, &escrow.mine);
                let final_sig = schnorr::SchnorrSig {
                    sig: signature,
                    hash_ty: SchnorrSighashType::Default,
                };
                tx.input[0].witness.push(final_sig.serialize());
                tx.input[0].witness.push(timelock_script.serialize());
                tx.input[0].witness.push(control_block.serialize());
            }
            SpendPath::Hashlock => {
                let hashlock_script = build_hashlock_script(
                    escrow.hashlock.as_bytes(),
                    &escrow.mine.x_only_public_key().0,
                );
                let control_block = self
                    .build_taproot_spend_info(self.role.other().clone())
                    .control_block(&(hashlock_script.clone(), LeafVersion::TapScript))
                    .unwrap();
                let sighash = sighash_cache
                    .taproot_script_spend_signature_hash(
                        0,
                        &Prevouts::All(&prevout),
                        TapLeafHash::from_script(&hashlock_script, LeafVersion::TapScript),
                        SchnorrSighashType::Default,
                    )
                    .unwrap();
                let message = secp256k1::Message::from(sighash);
                let signature = secp.sign_schnorr(&message, &escrow.mine);
                let final_sig = schnorr::SchnorrSig {
                    sig: signature,
                    hash_ty: SchnorrSighashType::Default,
                };
                tx.input[0].witness.push(final_sig.serialize());
                tx.input[0].witness.push(escrow.preimage.clone().unwrap());
                tx.input[0].witness.push(hashlock_script.serialize());
                tx.input[0].witness.push(control_block.serialize());
            }
            SpendPath::Keypath => {
                let sighash = sighash_cache
                    .taproot_key_spend_signature_hash(
                        0,
                        &Prevouts::All(&prevout),
                        SchnorrSighashType::Default,
                    )
                    .unwrap();
                let message = secp256k1::Message::from(sighash);
                let tweaked_keypair = self.calculate_escrow_privkey(&escrow)
                    .keypair(&secp)
                    .add_xonly_tweak(
                        &secp,
                        &self
                            .build_taproot_spend_info(self.role.clone())
                            .tap_tweak()
                            .to_scalar(),
                    )
                    .unwrap();
                let signature = secp.sign_schnorr(&message, &tweaked_keypair);
                let final_sig = schnorr::SchnorrSig {
                    sig: signature,
                    hash_ty: SchnorrSighashType::Default,
                };
                tx.input[0].witness.push(final_sig.serialize());
            }
        };

        Ok(tx)
    }
}

impl From<&mut Contract> for Proposal {
    fn from(value: &mut Contract) -> Proposal {
        Proposal {
            id: value.contract_id.clone(),
            network: value.network,
            maker_pubkey: value.maker_escrow.mine.public_key().clone(),
            taker_pubkey: value.taker_escrow.mine.public_key().clone(),
            hashlock: value.maker_escrow.hashlock.clone(),
            maker_timelock: value.maker_escrow.timelock.unwrap(),
            amount: Default::default(),
        }
    }
}

impl From<&mut Contract> for Offer {
    fn from(value: &mut Contract) -> Self {
        Offer {
            id: value.contract_id.clone(),
            maker_pubkey: value.maker_escrow.mine.public_key().clone(),
            taker_pubkey: value.taker_escrow.mine.public_key().clone(),
            taker_timelock: value.taker_escrow.timelock.unwrap(),
        }
    }
}

impl From<&mut Contract> for FinalizeDeal {
    fn from(value: &mut Contract) -> Self {
        FinalizeDeal {
            id: value.contract_id.clone(),
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
            timelock: Some(value.maker_timelock - 10), // taker should have a shorter timelock because they're at disadvantage for the hashlock
        };

        Contract {
            contract_id: value.id,
            network: value.network,
            state: Proposed,
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

    use crate::swap::contract::{Contract, ContractState, FinalizeDeal, Offer, Proposal, Role, SpendPath};

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

        let offer = Offer::from(&mut taker);
        // send that over nostr
        maker.accept_offer(offer);
        let finalize_deal = FinalizeDeal::from(&mut maker);
        // send that over NOSTR
        taker.finalize_deal(finalize_deal);

        // checks
        assert_eq!(maker.state, ContractState::Accepted);
        assert_eq!(taker.state, ContractState::Accepted);
        let maker_generated_maker_address = maker.get_address(Role::Maker);
        let maker_generated_taker_address = maker.get_address(Role::Taker);
        let taker_generated_maker_address = taker.get_address(Role::Maker);
        let taker_generated_taker_address = taker.get_address(Role::Taker);
        assert_eq!(
            maker.maker_escrow.mine.public_key(),
            taker.maker_escrow.their_pubkey.unwrap()
        );
        assert_eq!(
            taker.maker_escrow.mine.public_key(),
            maker.maker_escrow.their_pubkey.unwrap()
        );
        assert_eq!(
            maker.calculate_escrow_pubkey(Role::Maker).0,
            taker.calculate_escrow_pubkey(Role::Maker).0
        );
        assert_eq!(
            maker.calculate_escrow_pubkey(Role::Taker).0,
            taker.calculate_escrow_pubkey(Role::Taker).0
        );
        assert_eq!(
            maker.maker_escrow.timelock.unwrap(),
            taker.maker_escrow.timelock.unwrap()
        );
        assert_eq!(
            maker.taker_escrow.timelock.unwrap(),
            taker.taker_escrow.timelock.unwrap()
        );
        assert_eq!(maker_generated_maker_address, taker_generated_maker_address);
        assert_eq!(maker_generated_taker_address, taker_generated_taker_address);
        // end checks -- at this point we have both parties generating the same p2tr! woohoo!

        assert_eq!(maker.get_spend_path(0), SpendPath::Unspendable);
        assert_eq!(taker.get_spend_path(133), SpendPath::Unspendable);
        assert_eq!(taker.get_spend_path(134), SpendPath::Timelock);
        let preimage_reveal = maker.reveal_preimage().unwrap();
        taker.accept_preimage(preimage_reveal);
        assert_eq!(taker.get_spend_path(1), SpendPath::Hashlock);
        assert_eq!(maker.get_spend_path(1), SpendPath::Hashlock);
        let maker_key_reveal = maker.reveal_seckey().unwrap();
        let taker_key_reveal = taker.reveal_seckey().unwrap();
        maker.accept_seckey(taker_key_reveal);
        assert_eq!(maker.get_spend_path(1), SpendPath::Keypath);
        taker.accept_seckey(maker_key_reveal);
        assert_eq!(taker.get_spend_path(1), SpendPath::Keypath);
    }
}
