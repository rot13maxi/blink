extern crate core;

use std::collections::HashMap;

use bitcoin::{
    Address, Amount, EcdsaSighashType, KeyPair, Network, OutPoint, PackedLockTime, PublicKey,
    schnorr, SchnorrSighashType, Script, secp256k1, Sequence, Transaction, TxIn, TxOut,
    Witness, XOnlyPublicKey,
};
use bitcoin::blockdata::opcodes::all::{
    OP_CHECKSIGVERIFY, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_SHA256,
};
use bitcoin::blockdata::script;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::hex::ToHex;
use bitcoin::psbt::Prevouts;
use bitcoin::psbt::serialize::Serialize;
use bitcoin::secp256k1::{rand, Secp256k1, ThirtyTwoByteHash};
use bitcoin::util::sighash::SighashCache;
use bitcoin::util::taproot::TaprootBuilder;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoincore_rpc::bitcoincore_rpc_json::{CreateRawTransactionInput, EstimateMode};
use bitcoincore_rpc::json::SigHashType;
use nostr_sdk::Result;
use rand::RngCore;
use sha2::Digest;
use sha2::Sha256;

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
        .push_opcode(OP_CHECKSIGVERIFY)
        .into_script()
}

fn build_hashlock_script(hash: &[u8], pubkey: &XOnlyPublicKey) -> Script {
    script::Builder::new()
        .push_opcode(OP_SHA256)
        .push_slice(hash)
        .push_opcode(OP_EQUALVERIFY)
        .into_script()
}

#[tokio::main]
async fn main() -> Result<()> {
    let secp = Secp256k1::new();

    let alice = Participant::new();
    let bob = Participant::new();

    let alice_preimage = b"hello world";
    let mut hasher = Sha256::new();
    hasher.update(alice_preimage);
    let alice_hashlock = hasher.finalize();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(
            1u8,
            build_hashlock_script(
                alice_hashlock.as_slice(),
                &bob.hl_keypair.x_only_public_key().0,
            ),
        )
        .expect("couldn't add hashlock leaf")
        .add_leaf(
            1u8,
            build_timelock_script(2, &alice.refund_keypair.x_only_public_key().0),
        )
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
    // unload any existing wallets
    for wallet in rpc_client.list_wallets().expect("Could not list wallets") {
        rpc_client.unload_wallet(Some(&wallet));
    }

    println!("creating miner wallet and generating some corn");
    let miner_wallet_name = rpc_client
        .create_wallet(&format!("miner-{}", exec_id), None, None, None, None)
        .expect("Could not create miner wallet")
        .name;
    // mine some corn
    let miner_address = rpc_client
        .get_new_address(None, None)
        .expect("Could not get address for miner");
    rpc_client
        .generate_to_address(105, &miner_address)
        .expect("Could not generate blocks");

    // lets send some corn to that address
    println!("sending some corn to the alice->bob escrow address");
    let utxo = rpc_client
        .list_unspent(Some(101), None, None, None, None)
        .unwrap()
        .first()
        .unwrap()
        .clone();
    let mut alice_funding_output = HashMap::new();
    alice_funding_output.insert(alice2bob_addr.to_string(), Amount::ONE_BTC);
    alice_funding_output.insert(
        miner_address.to_string(),
        utxo.amount - Amount::ONE_BTC - Amount::from_sat(10000),
    );
    let raw_tx = rpc_client
        .create_raw_transaction(
            &[CreateRawTransactionInput {
                txid: utxo.txid,
                vout: utxo.vout,
                sequence: None,
            }],
            &alice_funding_output,
            None,
            None,
        )
        .expect("Couldnt create raw tx");
    let signed_tx = rpc_client
        .sign_raw_transaction_with_wallet(
            &raw_tx,
            None,
            Some(SigHashType::from(EcdsaSighashType::All)),
        )
        .expect("Couldn't sign raw tx");
    let first_funding_txid = rpc_client
        .send_raw_transaction(&signed_tx.hex)
        .expect("Couldn't send raw tx");
    println!("txid: {}", first_funding_txid.to_string());
    println!("generating a block to confirm it");
    rpc_client
        .generate_to_address(1, &miner_address)
        .expect("Could not generate blocks");

    println!("lets make sure the outpoint from that tx is what we think it is...");
    let signed_tx_hex = signed_tx.hex;
    let signed_tx_decoded = Transaction::consensus_decode(&mut signed_tx_hex.as_slice()).unwrap();
    assert_eq!(
        signed_tx_decoded.output[0].script_pubkey,
        alice2bob_addr.script_pubkey()
    );
    println!("looks good!");

    println!("Ok! Let's try to spend this sucker");
    println!("first up, lets do a key-path spend");

    let mut keypath_tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: first_funding_txid,
                vout: 0,
            },
            script_sig: script::Builder::new().into_script(), // this might be wrong
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_btc(0.99).unwrap().to_sat(),
            script_pubkey: miner_address.script_pubkey(),
        }],
    };

    let prevout = vec![&raw_tx.output[0]];

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
    let keypath_txid = rpc_client
        .send_raw_transaction(&keypath_tx.serialize())
        .expect("couldnt send keypath tx");

    println!("Worked! {}", keypath_txid);
    Ok(())
}
