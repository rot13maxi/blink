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
use bitcoin::util::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootBuilderError, TaprootSpendInfo};
use bitcoin::{
    schnorr, secp256k1, Address, KeyPair, Network, OutPoint, PackedLockTime,
    SchnorrSighashType, Script, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use serde::Deserialize;
use serde_json::json;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use rand::Rng;
use uuid::Uuid;
use crate::swap::components::{EscrowKeys, Hashlock, Timelock};
use crate::swap::role::Role;

use crate::swap::utxo::Utxo;
use thiserror::Error;
use crate::swap::contract::ContractError::{TaprootBuilderError, TapTreeError};
use crate::swap::role::Role::{Initiator, Participant};

const DEFAULT_TIMELOCK: u32 = 144; // blocks
const REQUIRED_CONFIRMATIONS: u32 = 1; // blocks

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("escrow key for `{0}` not available")]
    MissingKeys(Role),
    #[error("no private keys available for escrow")]
    NoPrivKeys,
    #[error("could not construct taptree: `{0}`")]
    TapTreeError(TaprootBuilderError),
    #[error("could not construct taproot info: `{0}`")]
    TaprootBuilderError(TaprootBuilder),
}

type Result<T> = std::result::Result<T, ContractError>;

#[derive(Deserialize, serde::Serialize, Debug)]
pub struct Contract {
    contract_id: String,
    escrow_keys: HashMap<Role, EscrowKeys>,
    hashlock: Hashlock,
    timelock: Timelock,
    utxo: Option<Utxo>, // someday, this will be Option<Vec<Utxo>> and then we'll REALLY be dangerous
}

impl Contract {
    pub fn new(network: Network) -> Self {
        let mut rng = rand::thread_rng();
        let contract_id_bytes: [u8;32] = rng.gen();
        let contract_id = contract_id_bytes.to_hex();
        let mut escrow_keys = HashMap::new();
        escrow_keys.insert(Role::Initiator, EscrowKeys::new());
        let hashlock = Hashlock::new();
        let timelock = Timelock::new(DEFAULT_TIMELOCK);
        Self {
            contract_id,
            escrow_keys,
            hashlock,
            timelock,
            utxo: None,
        }
    }

    fn calculate_shared_pubkey(&self) -> Result<XOnlyPublicKey> {
        let initiator_escrow = self.escrow_keys.get(&Initiator).ok_or(ContractError::MissingKeys(Initiator))?;
        let participant_escrow = self.escrow_keys.get(&Participant).ok_or(ContractError::MissingKeys(Participant))?;
        if let Some(pubkey) = initiator_escrow.calculate_shared_pubkey(participant_escrow) {
            Ok(pubkey)
        } else if let Some(pubkey) = participant_escrow.calculate_shared_pubkey(initiator_escrow) {
            Ok(pubkey)
        } else {
            Err(ContractError::NoPrivKeys)
        }
    }

    fn build_taproot_spend_info(&self, role: Role) -> Result<TaprootSpendInfo> {
        let secp = Secp256k1::new();
        Ok(TaprootBuilder::new()
            .add_leaf(
                1u8,
                self.hashlock.build_script(),
            )
            .map_err(|err| TapTreeError(err))?
            .add_leaf(
                1u8,
                self.timelock.build_script(),
            )
            .map_err(|err| TapTreeError(err))?
            .finalize(&secp, self.calculate_shared_pubkey()?)
            .map_err(|err| TaprootBuilderError(err))?)
    }

    pub(crate) fn get_address(&self, network: Network) -> Address {
        Address::p2tr_tweaked(
            self.build_taproot_spend_info().output_key(),
            network,
        )
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
                Role::Initiator => &self.maker_escrow,
                Role::Participant => &self.taker_escrow,
            }
        } else {
            match self.role {
                Role::Initiator => &self.taker_escrow,
                Role::Participant => &self.maker_escrow,
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
