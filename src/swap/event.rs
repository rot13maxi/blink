use crate::swap::message::SwapMessage;
use crate::swap::utxo::Utxo;
use bitcoin::Transaction;

pub(crate) enum SwapEvent {
    Start,
    MessageReceived(SwapMessage),
    BlockConfirmed(u64), // block height
    UtxoConfirmed(Utxo),
    UtxoSpent(Utxo, Transaction),
}
