use std::collections::HashMap;
use bitcoin::{Address, Network};
use crate::swap::contract::Contract;
use crate::swap::role::Role;
use serde::{Deserialize, Serialize};

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