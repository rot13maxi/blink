use std::str::FromStr;

use anyhow::{bail};
use bitcoin::{Address, Network};
use bitcoin::hashes::hex::ToHex;
use bitcoin::psbt::serialize::Serialize;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoincore_rpc::bitcoincore_rpc_json::ImportDescriptors;
use bitcoincore_rpc::json::Timestamp;
use clap::{Parser, Subcommand};

use crate::swap::contract::{Contract, FinalizeDeal, Offer, PreimageReveal, Proposal, Role};
use crate::swap::utxo::Utxo;

mod swap;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value_t = String::from("./blink_db"))]
    db_path: String,

    #[arg(short, long, default_value_t = Network::Regtest)]
    network: Network,

    #[arg(long)]
    rpc_username: Option<String>,

    #[arg(long)]
    rpc_password: Option<String>,

    #[arg(long, default_value_t = String::from("localhost"))]
    rpc_host: String,

    #[arg(long, default_value_t = 8332)]
    rpc_port: u16,

    #[arg(short, long, default_value_t = String::from("blink-wallet"))]
    wallet_name: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Deposit,
    Balance,
    Withdraw,
    #[command(subcommand)]
    Blink(BlinkCommand),
    Recover,
}

#[derive(Subcommand)]
enum BlinkCommand {
    CreateContract,
    ListContracts,
    Propose { id: String },
    Offer { proposal_blob: String },
    AcceptOffer {id: String, accept_offer_blob: String},
    FinalizeDeal {id: String, finalize_deal_blob: String},
    GetAddress {id: String, role: String},
    GetLocked {id: String},
    RevealPreimage {id: String},
    AcceptPreimage {id: String, preimage_blob: String},
    RevealKeys {id: String},
    AcceptKeys {id: String, seckey_blob: String},
    Close {id: String},
    Dump {id: String}
}


fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if (cli.rpc_username.is_some() && cli.rpc_password.is_none()) || (cli.rpc_username.is_none() && cli.rpc_password.is_some()) {
        bail!("You need to provide an rpc user AND password, or neither")
    }

    let tree = sled::open(cli.db_path)?;

    let rpc_client = Client::new(
        &format!("http://{}:{}", cli.rpc_host, cli.rpc_port),
        if cli.rpc_username.is_some() {
            Auth::UserPass("test".to_string(), "test".to_string())
        } else {Auth::None}
    )
        .expect("Couldn't make RPC client");

    let mut need_to_load_or_create = true;
    if let Ok(wallets) = rpc_client.list_wallets() {
        if wallets.len() == 1 && &wallets[0] == &cli.wallet_name {
            need_to_load_or_create = false;
        } else if wallets.len() > 0 {
            wallets.iter().for_each(|wallet| {
                if wallet == &cli.wallet_name {
                    need_to_load_or_create = false;
                } else {
                    println!("unloading {} so we don't accidentially touch it", wallet);
                    rpc_client.unload_wallet(Some(wallet)).expect("Could not unload wallet");
                }
            });
        }
    }
    if need_to_load_or_create {
        if let Err(_) = rpc_client.load_wallet(&cli.wallet_name) {
            println!("Creating new wallet named {}", &cli.wallet_name);
            rpc_client.create_wallet(&cli.wallet_name, Some(true), None, None, None)?;
        }
        println!("Wallet loaded");
    }


    match cli.command {
        Commands::Deposit => {
            let deposit_address = rpc_client.get_new_address(Some("deposit"), None)?;
            println!("{}", deposit_address);
        },
        Commands::Balance => {
            let confirmed = rpc_client.get_balance(Some(1), None)?;
            let total = rpc_client.get_balance(Some(0), None)?;
            println!("Confirmed: {}", confirmed);
            println!("In the mempool: {}", total - confirmed);
        }
        Commands::Withdraw => { println!("Withdraw not implemented!") }
        Commands::Blink(blink_command) => {
            match blink_command {
                BlinkCommand::CreateContract => {
                    let contract = Contract::new(cli.network);
                    tree.insert(contract.id(), serde_json::to_vec(&contract).unwrap().as_slice()).unwrap();
                    println!("Created offer for contract ID {}", contract.id());
                }
                BlinkCommand::ListContracts => {
                    tree.iter().for_each(|item| {
                        let (id_blob, contract_blob) = item.unwrap();
                        let id = std::str::from_utf8(id_blob.as_ref()).unwrap();
                        let contract: Contract = serde_json::from_slice(contract_blob.as_ref()).unwrap();
                        println!("{} -- {:?}", id, contract.state);
                    })
                }
                BlinkCommand::Propose { id } => {
                    let mut contract: Contract = serde_json::from_slice(tree.get(id).unwrap().unwrap().as_ref()).unwrap();
                    contract.propose();
                    tree.insert(contract.id(), serde_json::to_vec(&contract).unwrap().as_slice()).unwrap();
                }
                BlinkCommand::Offer { proposal_blob } => {
                    let proposal: Proposal = serde_json::from_str(&proposal_blob).unwrap();
                    let mut taker_contract = Contract::from(proposal);
                    let accept_proposal = Offer::from(&mut taker_contract);
                    tree.insert(taker_contract.id(), serde_json::to_vec(&taker_contract).unwrap().as_slice()).unwrap();
                    println!("{}", serde_json::to_string(&accept_proposal).unwrap());
                }
                BlinkCommand::AcceptOffer { id, accept_offer_blob } => {
                    let mut contract: Contract = serde_json::from_slice(tree.get(id.clone()).unwrap().unwrap().as_ref()).unwrap();
                    let offer: Offer = serde_json::from_str(&accept_offer_blob).unwrap();
                    contract.accept_offer(offer);
                    let finalize_deal = FinalizeDeal::from(&mut contract);
                    let address = contract.get_address(Role::Maker);
                    let spk = address.script_pubkey();
                    let gdi_result = rpc_client.get_descriptor_info(&format!("raw({})", spk.to_hex())).unwrap();
                    println!("Importing into wallet");
                    rpc_client.import_descriptors(ImportDescriptors {
                        descriptor: format!("{}", gdi_result.descriptor),
                        timestamp: Timestamp::Now,
                        label: Some(id),
                        active: None,
                        internal: None,
                        range: None,
                        next_index: None
                    }).unwrap();
                    println!("Done importing into wallet");
                    tree.insert(contract.id(), serde_json::to_vec(&contract).unwrap().as_slice()).unwrap();
                    println!("{}", serde_json::to_string(&finalize_deal).unwrap());
                }
                BlinkCommand::FinalizeDeal {id, finalize_deal_blob } => {
                    let mut taker_contract: Contract = serde_json::from_slice(tree.get(id.clone()).unwrap().unwrap().as_ref()).unwrap();
                    let finalize_deal: FinalizeDeal = serde_json::from_str(&finalize_deal_blob).unwrap();
                    taker_contract.finalize_deal(finalize_deal);
                    let address = taker_contract.get_address(Role::Taker);
                    let spk = address.script_pubkey();
                    let gdi_result = rpc_client.get_descriptor_info(&format!("raw({})", spk.to_hex())).unwrap();
                    println!("Importing into wallet");
                    rpc_client.import_descriptors(ImportDescriptors {
                        descriptor: format!("{}", gdi_result.descriptor),
                        timestamp: Timestamp::Now,
                        label: Some(id),
                        active: None,
                        internal: None,
                        range: None,
                        next_index: None
                    }).unwrap();
                    println!("Done importing into wallet");
                    tree.insert(taker_contract.id(), serde_json::to_vec(&taker_contract).unwrap().as_slice()).unwrap();
                }
                BlinkCommand::GetAddress {id, role} => {
                    let contract: Contract = serde_json::from_slice(tree.get(id).unwrap().unwrap().as_ref()).unwrap();
                    let address = contract.get_address(Role::from_str(&role).unwrap());
                    println!("{}", address);
                }
                BlinkCommand::GetLocked { id} => {
                    let contract: Contract = serde_json::from_slice(tree.get(id.clone()).unwrap().unwrap().as_ref()).unwrap();
                    let address = contract.get_address(contract.role.clone());
                    if escrow_confirmed(&rpc_client, 1, &address, 0)? {
                        println!("Ready to rock!");
                    } else {
                        if escrow_confirmed(&rpc_client, 0, &address, 0)? {
                            println!("In the mempool. waiting for confirmation");
                        } else {
                            println!("Nothing yet");
                        }
                    }
                }
                BlinkCommand::RevealPreimage { id } => {
                    let mut contract: Contract = serde_json::from_slice(tree.get(id.clone()).unwrap().unwrap().as_ref()).unwrap();
                    println!("{}", serde_json::to_string(&contract.reveal_preimage().unwrap()).unwrap());
                    tree.insert(contract.id(), serde_json::to_vec(&contract).unwrap().as_slice()).unwrap();

                }
                BlinkCommand::AcceptPreimage {id, preimage_blob} => {
                    let mut contract: Contract = serde_json::from_slice(tree.get(id.clone()).unwrap().unwrap().as_ref()).unwrap();
                    let reveal: PreimageReveal = serde_json::from_str(&preimage_blob).unwrap();
                    contract.accept_preimage(reveal);
                    tree.insert(contract.id(), serde_json::to_vec(&contract).unwrap().as_slice()).unwrap();
                }
                BlinkCommand::RevealKeys {..} => {}
                BlinkCommand::AcceptKeys {..} => {}
                BlinkCommand::Close { id } => {
                    let contract: Contract = serde_json::from_slice(tree.get(id.clone()).unwrap().unwrap().as_ref()).unwrap();
                    let address = contract.get_address(contract.role.clone());
                    let unspent = rpc_client.list_unspent(Some(1), None, Some(&[&address]), None, None).unwrap();
                    let utxo: Utxo = unspent[0].clone().into();
                    let spend_tx = contract.get_spending_tx(&utxo, Address::from_str("bcrt1qvqqlv224wflslj2g3wkq6kxm5thvagcac56ktj").unwrap(), None).unwrap();
                    println!("{}", spend_tx.serialize().to_hex());
                }

                BlinkCommand::Dump { id } =>
                    {
                        let contract: Contract = serde_json::from_slice(tree.get(id.clone()).unwrap().unwrap().as_ref()).unwrap();
                        println!("{:?}", contract);
                    }
            }
        }
        Commands::Recover => { println!("Recover not implemented!") }
    }

    Ok(())
}

fn escrow_confirmed(client: &Client, min_conf: usize, address: &Address, amount: u64) -> anyhow::Result<bool> {
    let unspent = client.list_unspent(Some(min_conf), None, Some(&[address]), None, None)?;
    let sum = unspent.iter().map(|utxo|utxo.amount.to_sat()).fold(0u64, |acc, x| acc + x);
    if sum >= amount && sum != 0 {
        Ok(true)
    } else {
        Ok(false)
    }
}