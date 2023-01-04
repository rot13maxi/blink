extern crate core;

use std::collections::HashMap;

use bitcoin::blockdata::opcodes::all::{
    OP_CHECKSIG, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_SHA256,
};
use bitcoin::blockdata::script;
use bitcoin::hashes::hex::ToHex;
use bitcoin::psbt::serialize::Serialize;
use bitcoin::psbt::Prevouts;
use bitcoin::secp256k1::{rand, Secp256k1};
use bitcoin::util::sighash::SighashCache;
use bitcoin::util::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{
    schnorr, secp256k1, Address, Amount, EcdsaSighashType, KeyPair, LockTime, Network, OutPoint,
    PackedLockTime, SchnorrSighashType, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    XOnlyPublicKey,
};
use bitcoin::hashes::{Hash, sha256};
use bitcoincore_rpc::bitcoincore_rpc_json::CreateRawTransactionInput;
use bitcoincore_rpc::json::SigHashType;
use bitcoincore_rpc::{Auth, Client, RawTx, RpcApi};
use nostr_sdk::Result;
use rand::RngCore;


struct Miner {
    client: Client,
}

impl Miner {
    fn new(rpc_client: Client) -> Self {
        // unload any existing wallets, create miner wallet if it doesn't exist
        for wallet in rpc_client.list_wallets().expect("Could not list wallets") {
            rpc_client.unload_wallet(Some(&wallet));
        }
        if let Err(_) = rpc_client.load_wallet("miner") {
            rpc_client.create_wallet("miner", None, None, None, None);
        }

        // make sure we have at least 100 bitcoin to use
        let miner_address = rpc_client.get_new_address(None, None).unwrap();
        while rpc_client.get_balance(Some(1), None).unwrap() < Amount::from_btc(100.0).unwrap() {
            rpc_client.generate_to_address(1, &miner_address).unwrap();
        }
        Self { client: rpc_client }
    }

    fn get_new_address(&self) -> Address {
        self.client.get_new_address(None, None).unwrap()
    }

    fn fund_address(&self, address: &Address, amount: Amount) -> Txid {
        let miner_address = self.client.get_new_address(None, None).unwrap();
        let utxo = self
            .client
            .list_unspent(Some(101), None, None, None, None)
            .unwrap()
            .first()
            .unwrap()
            .clone();
        let mut outputs = HashMap::new();
        outputs.insert(address.to_string(), amount);
        outputs.insert(
            miner_address.to_string(),
            utxo.amount - amount - Amount::from_sat(1000),
        );
        let raw_tx = self
            .client
            .create_raw_transaction(
                &[CreateRawTransactionInput {
                    txid: utxo.txid,
                    vout: utxo.vout,
                    sequence: None,
                }],
                &outputs,
                None,
                None,
            )
            .expect("Couldnt create raw tx");
        let signed_tx = self
            .client
            .sign_raw_transaction_with_wallet(
                &raw_tx,
                None,
                Some(SigHashType::from(EcdsaSighashType::All)),
            )
            .expect("Couldn't sign raw tx");
        let txid = self.client.send_raw_transaction(&signed_tx.hex).unwrap();
        self.gen_block();
        txid
    }

    fn gen_block(&self) {
        let miner_address = self.client.get_new_address(None, None).unwrap();
        self.client.generate_to_address(1, &miner_address).unwrap();
    }

    fn send_raw_tx<T>(&self, tx: T) -> Txid
    where
        T: RawTx,
    {
        self.client.send_raw_transaction(tx).unwrap()
    }

    fn get_block_height(&self) -> u64 {
        self.client.get_block_count().unwrap()
    }
}

struct Participant {
    refund_keypair: KeyPair,
    hl_keypair: KeyPair,
    escrow_keypair: KeyPair,
}

impl Participant {
    fn new() -> Self {
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
        let refund_keypair = KeyPair::from_secret_key(&secp, &secret_key);

        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
        let hl_keypair = KeyPair::from_secret_key(&secp, &secret_key);

        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
        let escrow_keypair = KeyPair::from_secret_key(&secp, &secret_key);

        Self {
            refund_keypair,
            hl_keypair,
            escrow_keypair,
        }
    }
}

fn build_timelock_script(nblocks: i64, pubkey: &XOnlyPublicKey) -> Script {
    script::Builder::new()
        .push_int(nblocks)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn build_hashlock_script(hash: &[u8], pubkey: &XOnlyPublicKey) -> Script {
    script::Builder::new()
        .push_opcode(OP_SHA256)
        .push_slice(hash)
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

#[tokio::main]
async fn main() -> Result<()> {
    let secp = Secp256k1::new();

    let alice = Participant::new();
    let bob = Participant::new();

    let alice_preimage = b"hello world";
    let alice_hashlock = sha256::Hash::hash(alice_preimage);

    let timelock_script = build_timelock_script(3, &alice.refund_keypair.x_only_public_key().0);
    let hashlock_script = build_hashlock_script(
        alice_hashlock.serialize().as_slice(),
        &bob.hl_keypair.x_only_public_key().0,
    );

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(1u8, hashlock_script.clone())
        .expect("couldn't add hashlock leaf")
        .add_leaf(1u8, timelock_script.clone())
        .expect("Couldn't add timelock leaf")
        .finalize(&secp, alice.escrow_keypair.x_only_public_key().0)
        .expect("Could not finalize taproot spend info");

    let alice2bob_addr = Address::p2tr_tweaked(taproot_spend_info.output_key(), Network::Regtest);
    println!(
        "I think we have an address? maybe? {}",
        alice2bob_addr.to_string()
    );

    // Start of code to test shit out
    let mut rng = rand::thread_rng();
    let exec_id: u64 = rng.next_u64();
    let rpc_client = Client::new(
        "http://localhost:8333",
        Auth::UserPass("test".to_string(), "test".to_string()),
    )
    .expect("Couldn't make RPC client");

    let miner = Miner::new(rpc_client);

    let funding_txid = miner.fund_address(&alice2bob_addr, Amount::ONE_BTC);

    println!("Ok! Let's try to spend this sucker");
    println!("first up, lets do a key-path spend");

    let mut keypath_tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: funding_txid,
                vout: 0,
            },
            script_sig: script::Builder::new().into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_btc(0.99).unwrap().to_sat(),
            script_pubkey: miner.get_new_address().script_pubkey(),
        }],
    };

    let funding_output = TxOut {
        value: Amount::ONE_BTC.to_sat(),
        script_pubkey: alice2bob_addr.script_pubkey(),
    };

    let prevout = vec![&funding_output];

    let mut sighash_cache = SighashCache::new(&keypath_tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevout), SchnorrSighashType::All)
        .unwrap();

    let message = secp256k1::Message::from(sighash);
    let tweaked_keypair = alice
        .escrow_keypair
        .add_xonly_tweak(&secp, &taproot_spend_info.tap_tweak().to_scalar())
        .unwrap();
    let signature = secp.sign_schnorr(&message, &tweaked_keypair);

    println!("lets verify that signature...");
    secp.verify_schnorr(
        &signature,
        &message,
        &taproot_spend_info.output_key().to_inner(),
    )
    .unwrap();
    println!("looks like a good sig to me!");

    let final_sig = schnorr::SchnorrSig {
        sig: signature,
        hash_ty: SchnorrSighashType::All,
    };
    keypath_tx.input[0].witness.push(final_sig.serialize());

    println!(
        "here's the raw transaction: {}",
        &keypath_tx.serialize().to_hex()
    );
    println!("trying to send it.");
    let keypath_txid = miner.send_raw_tx(&keypath_tx.serialize());
    miner.gen_block();
    println!("Worked! {}", keypath_txid);

    println!("Now lets try doing a timelock spend");
    let funding_txid = miner.fund_address(&alice2bob_addr, Amount::ONE_BTC);
    let control_block = taproot_spend_info
        .control_block(&(timelock_script.clone(), LeafVersion::TapScript))
        .unwrap();
    let block_height = miner.get_block_height();
    let mut timelock_tx = Transaction {
        version: 2,
        //lock_time: LockTime::Blocks(Height::from_consensus(2 + block_height as u32).unwrap()).into(),
        lock_time: PackedLockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: funding_txid,
                vout: 0,
            },
            script_sig: script::Builder::new().into_script(),
            sequence: Sequence::from_height(3),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_btc(0.99).unwrap().to_sat(),
            script_pubkey: miner.get_new_address().script_pubkey(),
        }],
    };

    let funding_output = TxOut {
        value: Amount::ONE_BTC.to_sat(),
        script_pubkey: alice2bob_addr.script_pubkey(),
    };

    let prevout = vec![&funding_output];

    let mut sighash_cache = SighashCache::new(&timelock_tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevout),
            TapLeafHash::from_script(&timelock_script, LeafVersion::TapScript),
            SchnorrSighashType::Default,
        )
        .unwrap();
    let message = secp256k1::Message::from(sighash);
    let signature = secp.sign_schnorr(&message, &alice.refund_keypair);
    secp.verify_schnorr(
        &signature,
        &message,
        &alice.refund_keypair.x_only_public_key().0,
    )
    .expect("bad signature on timelock tx");
    let final_sig = schnorr::SchnorrSig {
        sig: signature,
        hash_ty: SchnorrSighashType::Default,
    };
    timelock_tx.input[0].witness.push(final_sig.serialize());
    timelock_tx.input[0]
        .witness
        .push(timelock_script.serialize());
    timelock_tx.input[0].witness.push(control_block.serialize());
    println!(
        "here's the raw transaction: {}",
        &timelock_tx.serialize().to_hex()
    );

    println!("Let's tick over two blocks (for a total of three)");
    miner.gen_block();
    miner.gen_block();

    println!("trying to send it.");
    let timelock_txid = miner.send_raw_tx(&timelock_tx.serialize());
    miner.gen_block();
    println!("Worked! {}", timelock_txid);

    println!("For our last trick, we'll try a hashlock spend");
    let funding_txid = miner.fund_address(&alice2bob_addr, Amount::ONE_BTC);
    let control_block = taproot_spend_info
        .control_block(&(hashlock_script.clone(), LeafVersion::TapScript))
        .unwrap();

    let mut hashlock_tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: funding_txid,
                vout: 0,
            },
            script_sig: script::Builder::new().into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_btc(0.99).unwrap().to_sat(),
            script_pubkey: miner.get_new_address().script_pubkey(),
        }],
    };

    let funding_output = TxOut {
        value: Amount::ONE_BTC.to_sat(),
        script_pubkey: alice2bob_addr.script_pubkey(),
    };

    let prevout = vec![&funding_output];

    let mut sighash_cache = SighashCache::new(&hashlock_tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevout),
            TapLeafHash::from_script(&hashlock_script, LeafVersion::TapScript),
            SchnorrSighashType::Default,
        )
        .unwrap();
    let message = secp256k1::Message::from(sighash);
    let signature = secp.sign_schnorr(&message, &bob.hl_keypair);
    secp.verify_schnorr(&signature, &message, &bob.hl_keypair.x_only_public_key().0)
        .expect("bad signature on hashlock tx");
    let final_sig = schnorr::SchnorrSig {
        sig: signature,
        hash_ty: SchnorrSighashType::Default,
    };
    hashlock_tx.input[0].witness.push(final_sig.serialize());
    hashlock_tx.input[0].witness.push(alice_preimage);
    hashlock_tx.input[0]
        .witness
        .push(hashlock_script.serialize());
    hashlock_tx.input[0].witness.push(control_block.serialize());
    println!(
        "here's the raw transaction: {}",
        &hashlock_tx.serialize().to_hex()
    );

    println!("trying to send it.");
    let hashlock_txid = miner.send_raw_tx(&hashlock_tx.serialize());
    miner.gen_block();
    println!("Worked! {}", hashlock_txid);

    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::secp256k1::{Message, Scalar, Secp256k1};

    #[test]
    fn test_that_we_can_smash_privkeys_together() {
        let secp = Secp256k1::new();
        let (seckey_a, pubkey_a) = secp.generate_keypair(&mut rand::thread_rng());
        let (seckey_b, pubkey_b) = secp.generate_keypair(&mut rand::thread_rng());

        // alice sends bob her pubkey

        let shared_pubkey = pubkey_a.mul_tweak(&secp, &Scalar::from(seckey_b)).unwrap();
        let bob2alice_pubkey = pubkey_b.mul_tweak(&secp, &Scalar::from(seckey_a)).unwrap();
        assert_eq!(shared_pubkey, bob2alice_pubkey);
        let shared_seckey = seckey_a.mul_tweak(&Scalar::from(seckey_b)).unwrap();

        let h = sha256::Hash::hash(b"Hello, World");
        let message = Message::from(h);
        let sig = secp.sign_schnorr(&message, &shared_seckey.keypair(&secp));
        secp.verify_schnorr(&sig, &message, &shared_pubkey.x_only_public_key().0).unwrap()
    }
}