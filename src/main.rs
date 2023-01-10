use anyhow::bail;
use bitcoin::{Address, Network};

use bitcoincore_rpc::{Auth, Client, RpcApi};

use clap::{Parser, Subcommand};

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
    Propose {
        id: String,
    },
    Offer {
        proposal_blob: String,
    },
    AcceptOffer {
        id: String,
        accept_offer_blob: String,
    },
    FinalizeDeal {
        id: String,
        finalize_deal_blob: String,
    },
    GetAddress {
        id: String,
        role: String,
    },
    GetLocked {
        id: String,
    },
    RevealPreimage {
        id: String,
    },
    AcceptPreimage {
        id: String,
        preimage_blob: String,
    },
    RevealKeys {
        id: String,
    },
    AcceptKeys {
        id: String,
        seckey_blob: String,
    },
    Close {
        id: String,
    },
    Dump {
        id: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if (cli.rpc_username.is_some() && cli.rpc_password.is_none())
        || (cli.rpc_username.is_none() && cli.rpc_password.is_some())
    {
        bail!("You need to provide an rpc user AND password, or neither")
    }

    let tree = sled::open(cli.db_path)?;

    let rpc_client = Client::new(
        &format!("http://{}:{}", cli.rpc_host, cli.rpc_port),
        if cli.rpc_username.is_some() {
            Auth::UserPass("test".to_string(), "test".to_string())
        } else {
            Auth::None
        },
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
                    rpc_client
                        .unload_wallet(Some(wallet))
                        .expect("Could not unload wallet");
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

    Ok(())
}

fn escrow_confirmed(
    client: &Client,
    min_conf: usize,
    address: &Address,
    amount: u64,
) -> anyhow::Result<bool> {
    let unspent = client.list_unspent(Some(min_conf), None, Some(&[address]), None, None)?;
    let sum = unspent
        .iter()
        .map(|utxo| utxo.amount.to_sat())
        .fold(0u64, |acc, x| acc + x);
    if sum >= amount && sum != 0 {
        Ok(true)
    } else {
        Ok(false)
    }
}
