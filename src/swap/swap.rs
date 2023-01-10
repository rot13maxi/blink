use crate::swap::contract::Contract;
use crate::swap::role::Role;
use bitcoin::hashes::hex::ToHex;
use bitcoin::{Address, Network, Transaction};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Deref;
use crate::swap::event::SwapEvent;
use crate::swap::message::{Proposal, SwapMessage};

#[derive(Deserialize, Serialize, Debug)]
pub(crate) enum SwapInstruction {
    SendMessage(SwapMessage),
    SendTransaction(Transaction),
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
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
    pub(crate) swap_id: String,
    pub(crate) network: Network,
    pub(crate) role: Role,
    pub(crate) state: SwapState,
    pub(crate) amount: u64,
    pub(crate) destination: Address,
    pub(crate) contracts: HashMap<Role, Contract>,
}

impl Swap {
    /// Advance the swap state machine by one step. This is the core state-transition function
    /// This is not meant to be called manually, but in a loop that feeds events
    /// from nostr and bitcoind into the state machine to process.
    /// The `backlog` should be a mutable reference to a queue of events
    /// that the state machine can't process (yet). it is used to re-drive events
    /// that arrive out of order.
    /// Returns a SwapInstruction, which is an instruction to either send a nostr event
    /// or to publish a bitcoin transaction. The executor that's driving the state machine
    /// is responsible for the actual IO to make that happen.
    fn step(&mut self, event: SwapEvent, backlog: &mut Vec<SwapEvent>) -> Option<SwapInstruction> {
        match event {
            SwapEvent::Start => {
                if self.state == SwapState::Init {
                    self.state = SwapState::Proposed;
                    Some(SwapInstruction::SendMessage(SwapMessage::Proposal(self.deref().into())))
                } else {
                    // if we're not at the init state, discard.
                    None
                }
            }
            SwapEvent::MessageReceived(msg) => {
                match msg {
                    SwapMessage::Proposal(_) => {
                        // How do we start a Participant?
                        None
                    }
                    SwapMessage::Offer(_) => {None}
                    SwapMessage::OfferResponse(_) => {None}
                    SwapMessage::AddressConfirmation(_) => {None}
                    SwapMessage::PreimageReveal(_) => {None}
                    SwapMessage::KeyReveal(_) => {None}
                }
            }
            SwapEvent::BlockConfirmed(_) => {None}
            SwapEvent::UtxoConfirmed(_) => {None}
            SwapEvent::UtxoSpent(_, _) => {None}
        }
    }

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
