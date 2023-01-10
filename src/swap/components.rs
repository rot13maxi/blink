use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_SHA256};
use bitcoin::blockdata::script;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{Script, XOnlyPublicKey};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct EscrowKeys {
    pubkey: Option<PublicKey>,
    seckey: Option<SecretKey>,
}

impl EscrowKeys {
    pub(crate) fn new() -> Self {
        let secp = Secp256k1::new();
        let (seckey, pubkey) = secp.generate_keypair(&mut rand::thread_rng());
        Self {
            pubkey: Some(pubkey),
            seckey: Some(seckey),
        }
    }

    pub(crate) fn calculate_shared_pubkey(&self, other: &EscrowKeys) -> Option<XOnlyPublicKey> {
        let secp = Secp256k1::new();
        Some(
            other
                .pubkey?
                .mul_tweak(&secp, &Scalar::from(self.seckey?))
                .ok()?
                .x_only_public_key()
                .0,
        )
    }

    pub(crate) fn calculate_shared_seckey(&self, other: &EscrowKeys) -> Option<SecretKey> {
        Some(other.seckey?.mul_tweak(&Scalar::from(self.seckey?)).ok()?)
    }
}

impl From<PublicKey> for EscrowKeys {
    fn from(value: PublicKey) -> Self {
        Self {
            seckey: None,
            pubkey: Some(value),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct Hashlock {
    hash: String,
    pub(crate) preimage: Option<String>,
    pubkey: XOnlyPublicKey,
    pub(crate) seckey: Option<SecretKey>,
}

impl Hashlock {
    pub(crate) fn new() -> Self {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let (seckey, pubkey) = secp.generate_keypair(&mut rng);
        let preimage_bytes: [u8; 32] = rng.gen();
        let preimage = preimage_bytes.to_hex();
        let hash = sha256::Hash::hash(preimage.as_bytes());
        Self {
            hash: hash.to_string(),
            preimage: Some(preimage),
            pubkey: pubkey.x_only_public_key().0,
            seckey: Some(seckey),
        }
    }

    pub(crate) fn build_script(&self) -> Script {
        script::Builder::new()
            .push_opcode(OP_SHA256)
            .push_slice(self.hash.as_bytes())
            .push_opcode(OP_EQUALVERIFY)
            .push_x_only_key(&self.pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }
}

impl From<(String, XOnlyPublicKey)> for Hashlock {
    /// Convert from a (hash, pubkey) to a hashlock
    fn from(value: (String, XOnlyPublicKey)) -> Self {
        Self {
            preimage: None,
            seckey: None,
            hash: value.0,
            pubkey: value.1,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct Timelock {
    pub(crate) nblocks: u16,
    pubkey: XOnlyPublicKey,
    pub(crate) seckey: Option<SecretKey>,
}

impl Timelock {
    pub(crate) fn new(nblocks: u16) -> Self {
        let secp = Secp256k1::new();
        let (seckey, pubkey) = secp.generate_keypair(&mut rand::thread_rng());
        Self {
            nblocks,
            pubkey: pubkey.x_only_public_key().0,
            seckey: Some(seckey),
        }
    }
    pub(crate) fn build_script(&self) -> Script {
        script::Builder::new()
            .push_int(self.nblocks as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&self.pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }
}
