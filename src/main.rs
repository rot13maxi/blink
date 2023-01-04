mod lib;

use anyhow::{anyhow, bail};
use bitcoin::Network;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use clap::{Parser, Subcommand};
use nostr_sdk::nostr::event::TagKind::P;


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
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
    CreateOffer,
    Propose { id: String },
    Accept {id: String},
    Reveal {id: String},
    Close {id: String},
}

/// Protocol is something like:
/// Alice and Bob
/// Alice -> Bob: Offer(id, PubKeys, Hashlock, myTimelock, amount)
/// Bob -> Alice: Propose(id, PubKeys, myTimelock)
/// Alice -> Bob: Accept(id)
/// Bob -> Alice: Accept(id)
/// Alice -> Bob: Reveal(id, preImage)
/// Bob -> Alice: Close(id, secKey)
/// Alice -> Bob: Close(id, secKey)

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if (cli.rpc_username.is_some() && cli.rpc_password.is_none()) || (cli.rpc_username.is_none() && cli.rpc_password.is_some()) {
        bail!("You need to provide an rpc user AND password, or neither")
    }

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
            rpc_client.create_wallet(&cli.wallet_name, None, None, None, None)?;
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
                BlinkCommand::CreateOffer => {}
                BlinkCommand::Propose { .. } => {}
                BlinkCommand::Accept { .. } => {}
                BlinkCommand::Reveal { .. } => {}
                BlinkCommand::Close { .. } => {}
            }
        }
        Commands::Recover => { println!("Recover not implemented!") }
    }

    Ok(())
}