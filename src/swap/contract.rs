use std::collections::HashMap;
use std::fmt::Formatter;

use bitcoin::blockdata::opcodes::all::{OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_SHA256};
use bitcoin::blockdata::script;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::serialize::Serialize;
use bitcoin::psbt::Prevouts;
use bitcoin::secp256k1::{Parity, Scalar, Secp256k1, SecretKey};
use bitcoin::util::sighash::SighashCache;
use bitcoin::util::taproot::{
    LeafVersion, TapLeafHash, TaprootBuilder, TaprootBuilderError, TaprootSpendInfo,
};
use bitcoin::{
    schnorr, secp256k1, Address, KeyPair, Network, OutPoint, PackedLockTime, SchnorrSighashType,
    Script, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use rand::Rng;
use serde::Deserialize;
use thiserror::Error;

use crate::swap::components::{EscrowKeys, Hashlock, Timelock};
use crate::swap::role::Role;
use crate::swap::role::Role::{Initiator, Participant};
use crate::swap::utxo::Utxo;

const DEFAULT_TIMELOCK: u16 = 144; // blocks
const REQUIRED_CONFIRMATIONS: u32 = 1; // blocks

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("escrow key for `{0}` not available")]
    MissingKeys(Role),
    #[error("no private keys available for escrow")]
    NoPrivKeys,
    #[error("could not construct taptree: `{0}`")]
    TapTreeError(TaprootBuilderError),
    #[error("could not finalize taproot info`")]
    TaprootFinalizationError,
    #[error("could not construct transaction: `{0}")]
    TransactionConstructionError(String),
    #[error("no UTXO found for contract")]
    NoUtxoError,
    #[error("could not construct sighash: `{0}`")]
    ScriptHashError(String),
    #[error("can't tweak private key: `{0}1")]
    CantTweakKey(String),
    #[error("missing hashlock preimage")]
    PreimageMissing,
}

type Result<T> = std::result::Result<T, ContractError>;

#[derive(PartialEq)]
pub enum SpendPath {
    KeyPath,
    Hashlock,
    Timelock,
}

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
        let contract_id_bytes: [u8; 32] = rng.gen();
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
        let initiator_escrow = self
            .escrow_keys
            .get(&Initiator)
            .ok_or(ContractError::MissingKeys(Initiator))?;
        let participant_escrow = self
            .escrow_keys
            .get(&Participant)
            .ok_or(ContractError::MissingKeys(Participant))?;
        if let Some(pubkey) = initiator_escrow.calculate_shared_pubkey(participant_escrow) {
            Ok(pubkey)
        } else if let Some(pubkey) = participant_escrow.calculate_shared_pubkey(initiator_escrow) {
            Ok(pubkey)
        } else {
            Err(ContractError::NoPrivKeys)
        }
    }

    fn calculate_shared_seckey(&self) -> Result<SecretKey> {
        let initiator_seckey = self
            .escrow_keys
            .get(&Initiator)
            .ok_or(ContractError::MissingKeys(Initiator))?;
        let participant_escrow = self
            .escrow_keys
            .get(&Participant)
            .ok_or(ContractError::MissingKeys(Participant))?;
        initiator_seckey
            .calculate_shared_seckey(participant_escrow)
            .ok_or(ContractError::NoPrivKeys)
    }

    fn build_taproot_spend_info(&self) -> Result<TaprootSpendInfo> {
        let secp = Secp256k1::new();
        Ok(TaprootBuilder::new()
            .add_leaf(1u8, self.hashlock.build_script())
            .map_err(|err| ContractError::TapTreeError(err))?
            .add_leaf(1u8, self.timelock.build_script())
            .map_err(|err| ContractError::TapTreeError(err))?
            .finalize(&secp, self.calculate_shared_pubkey()?)
            .map_err(|_| ContractError::TaprootFinalizationError)?)
    }

    pub(crate) fn get_address(&self, network: Network) -> Result<Address> {
        Ok(Address::p2tr_tweaked(
            self.build_taproot_spend_info()?.output_key(),
            network,
        ))
    }

    /// Get a signed, ready-to-send TX that spends the contract
    pub fn get_spending_tx(
        &self,
        spend_path: SpendPath,
        destination: Address,
        fee_rate: Option<u64>,
    ) -> Result<Transaction> {
        // TODO: actually calculate transaction size so we can do better fee calculation
        // Just picking a number for now. will probably be overpaying in most cases
        let tx_vbytes = 600;
        let fee = tx_vbytes * fee_rate.unwrap_or(1);
        let mut tx: Transaction = Transaction {
            version: 2,
            lock_time: PackedLockTime::ZERO,
            input: vec![TxIn {
                previous_output: self.utxo.as_ref().ok_or(ContractError::NoUtxoError)?.into(),
                script_sig: script::Builder::new().into_script(),
                sequence: if spend_path == SpendPath::Timelock {
                    Sequence::from_height(self.timelock.nblocks)
                } else {
                    Sequence::MAX
                },
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: self.utxo.as_ref().ok_or(ContractError::NoUtxoError)?.amount - fee,
                script_pubkey: destination.script_pubkey(),
            }],
        };
        let prevout: Vec<TxOut> =
            vec![self.utxo.as_ref().ok_or(ContractError::NoUtxoError)?.into()];
        let secp = Secp256k1::new();
        let mut sighash_cache = SighashCache::new(&tx);
        let witness = match spend_path {
            SpendPath::KeyPath => {
                let sighash = sighash_cache
                    .taproot_key_spend_signature_hash(
                        0,
                        &Prevouts::All(&prevout),
                        SchnorrSighashType::Default,
                    )
                    .map_err(|e| ContractError::ScriptHashError(e.to_string()))?;
                let message = secp256k1::Message::from(sighash);
                let tweaked_keypair = self
                    .calculate_shared_seckey()?
                    .keypair(&secp)
                    .add_xonly_tweak(
                        &secp,
                        &self.build_taproot_spend_info()?.tap_tweak().to_scalar(),
                    )
                    .map_err(|err| ContractError::CantTweakKey(err.to_string()))?;
                let signature = secp.sign_schnorr(&message, &tweaked_keypair);
                let final_sig = schnorr::SchnorrSig {
                    sig: signature,
                    hash_ty: SchnorrSighashType::Default,
                };
                vec![final_sig.serialize()]
            }
            SpendPath::Hashlock => {
                let hashlock_script = self.hashlock.build_script();
                let control_block = self
                    .build_taproot_spend_info()?
                    .control_block(&(hashlock_script.clone(), LeafVersion::TapScript))
                    .ok_or(ContractError::TaprootFinalizationError)?;
                let sighash = sighash_cache
                    .taproot_script_spend_signature_hash(
                        0,
                        &Prevouts::All(&prevout),
                        TapLeafHash::from_script(&hashlock_script, LeafVersion::TapScript),
                        SchnorrSighashType::Default,
                    )
                    .map_err(|err| ContractError::ScriptHashError(err.to_string()))?;
                let message = secp256k1::Message::from(sighash);
                let keypair = KeyPair::from_secret_key(
                    &secp,
                    &self.hashlock.seckey.ok_or(ContractError::NoPrivKeys)?,
                );
                let signature = secp.sign_schnorr(&message, &keypair);
                let final_sig = schnorr::SchnorrSig {
                    sig: signature,
                    hash_ty: SchnorrSighashType::Default,
                };
                vec![
                    final_sig.serialize(),
                    Vec::from(
                        self.hashlock
                            .preimage
                            .as_ref()
                            .ok_or(ContractError::PreimageMissing)?
                            .clone()
                            .as_bytes(),
                    ),
                    hashlock_script.serialize(),
                    control_block.serialize(),
                ]
            }
            SpendPath::Timelock => {
                let timelock_script = self.timelock.build_script();
                let control_block = self
                    .build_taproot_spend_info()?
                    .control_block(&(timelock_script.clone(), LeafVersion::TapScript))
                    .ok_or(ContractError::TaprootFinalizationError)?;
                let sighash = sighash_cache
                    .taproot_script_spend_signature_hash(
                        0,
                        &Prevouts::All(&prevout),
                        TapLeafHash::from_script(&timelock_script, LeafVersion::TapScript),
                        SchnorrSighashType::Default,
                    )
                    .map_err(|err| ContractError::ScriptHashError(err.to_string()))?;
                let message = secp256k1::Message::from(sighash);
                let keypair = KeyPair::from_secret_key(
                    &secp,
                    &self.timelock.seckey.ok_or(ContractError::NoPrivKeys)?,
                );
                let signature = secp.sign_schnorr(&message, &keypair);
                let final_sig = schnorr::SchnorrSig {
                    sig: signature,
                    hash_ty: SchnorrSighashType::Default,
                };
                vec![
                    final_sig.serialize(),
                    timelock_script.serialize(),
                    control_block.serialize(),
                ]
            }
        };
        for item in witness {
            tx.input[0].witness.push(item);
        }

        Ok(tx)
    }
}
