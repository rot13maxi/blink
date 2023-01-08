use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{Script, XOnlyPublicKey};
use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_SHA256};
use bitcoin::blockdata::script;
use serde::{Serialize, Deserialize};


#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct EscrowKeys {
    pubkey: Option<PublicKey>,
    seckey: Option<SecretKey>,
}

impl EscrowKeys {
    fn calculate_shared_pubkey(&self, other: &EscrowKeys) -> Option<XOnlyPublicKey> {
        let secp = Secp256k1::new();
        Some(other.pubkey?.mul_tweak(&secp, &Scalar::from(self.seckey?)).ok()?.x_only_public_key().0)
    }

    fn calculate_shared_seckey(&self, other: &EscrowKeys) -> Option<SecretKey> {
        Some(other.seckey?.mul_tweak(&Scalar::from(self.seckey?)).ok()?)
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct Hashlock {
    hash: String,
    preimage: Option<String>,
    pubkey: XOnlyPublicKey,
    seckey: Option<SecretKey>,
}

impl Hashlock {
    fn build_script(&self) -> Script {
        script::Builder::new()
            .push_opcode(OP_SHA256)
            .push_slice(self.hash.as_bytes())
            .push_opcode(OP_EQUALVERIFY)
            .push_x_only_key(&self.pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct Timelock {
    n_blocks: u32,
    pubkey: XOnlyPublicKey,
    seckey: Option<SecretKey>,
}

impl Timelock {
    fn build_script(&self) -> Script {
        script::Builder::new()
            .push_int(self.n_blocks as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&self.pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }
}