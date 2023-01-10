use crate::swap::contract::Contract;
use crate::swap::role::Role;
use bitcoin::hashes::hex::ToHex;
use bitcoin::{Address, Network};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Serialize, Debug)]
pub(crate) enum SwapState {
    Init,
    Proposed,
    Offered,
    Bootstrapped,
    PendingLock,
    Deposited,
    PreimageRevealed,
    SecKeyRevealed,
    Closable,
    ClosedSuccess,
    ClosedHashlock,
    ClosedTimelock,
    RefundSpend,
    HashlockSpend,
    TimedOut,
}

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct Swap {
    swap_id: String,
    network: Network,
    role: Role,
    state: SwapState,
    amount: u64,
    destination: Address,
    contracts: HashMap<Role, Contract>,
}

impl Swap {
    fn new(network: Network, amount: u64, destination: Address) -> Self {
        let mut rng = rand::thread_rng();
        let swap_id_bytes: [u8; 32] = rng.gen();
        let swap_id = swap_id_bytes.to_hex();
        let mut contracts = HashMap::new();
        contracts.insert(Role::Initiator, Contract::new(network));
        Self {
            swap_id,
            network,
            role: Role::Initiator,
            state: SwapState::Init,
            amount,
            destination,
            contracts,
        }
    }
}
