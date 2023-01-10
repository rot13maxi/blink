use bitcoin::{Amount, OutPoint, Script, TxOut};
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

impl From<&Utxo> for OutPoint {
    fn from(value: &Utxo) -> Self {
        OutPoint {
            txid: value.txid,
            vout: value.vout,
        }
    }
}

impl From<&Utxo> for TxOut {
    fn from(value: &Utxo) -> Self {
        TxOut {
            script_pubkey: value.script_pub_key.clone(),
            value: value.amount,
        }
    }
}
