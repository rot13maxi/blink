use bitcoin::{KeyPair, PrivateKey, XOnlyPublicKey};
use bitcoin::hashes::sha256::Hash;
use bitcoin::secp256k1::Secp256k1;
use uuid::Uuid;
use crate::lib::contract::ContractState::Init;

const DEFAULT_TIMELOCK: u16 = 10;

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

enum Role {
    Maker,
    Taker
}

struct EscrowKeys {
    mine: KeyPair,
    their_pubkey: Option<XOnlyPublicKey>,
    their_privkey: Option<PrivateKey>,
}

pub struct Contract {
    id: String,
    state: ContractState,
    role: Role,
    my_escrow: EscrowKeys,
    their_escrow: EscrowKeys,
    preimage: Option<String>,
    hashlock: Option<Hash>,
    my_timelock: u16,
    counterparty_timelock: Option<u16>,
}

impl Contract {
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
        Self {
            id: Uuid::new_v4().to_string(),
            state: Init,
            role,
            my_escrow,
            their_escrow,
            preimage: None,
            hashlock: None,
            my_timelock: DEFAULT_TIMELOCK,
            counterparty_timelock: None,
        }
    }


}