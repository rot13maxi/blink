use bitcoin::{Amount, Script};
use bitcoincore_rpc::json::ListUnspentResultEntry;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct Utxo {
    pub txid: bitcoin::Txid,
    pub vout: u32,
    pub script_pub_key: Script,
    pub amount: u64,
    pub confirmations: u32,
}

impl From<ListUnspentResultEntry> for Utxo {
    fn from(value: ListUnspentResultEntry) -> Self {
        Utxo {
            txid: value.txid,
            vout: value.vout,
            script_pub_key: value.script_pub_key,
            amount: value.amount.to_sat(),
            confirmations: value.confirmations,
        }
    }
}