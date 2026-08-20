use clap::{Parser, Subcommand};
use hc_seed_bundle::SharedLockedArray;
use hc_seed_bundle::dependencies::sodoken::LockedArray;
use holo_hash::AgentPubKeyB64;
use holochain_types::prelude::InstalledAppId;
use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
pub struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand, Debug)]
pub enum CliCommand {
    /// Generate a seed bundle that can be imported into Lair keystore.
    SeedBundle {
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Generate a bare signing keypair that is not protected as a seed bundle.
    BareSigningKeypair,
    /// Join the joining service with a given progenitor.
    JoiningServiceJoin {
        #[clap(long)]
        seed_bundle: PathBuf,

        #[clap(long)]
        seed_bundle_passphrase: Option<String>,

        #[clap(long)]
        joining_service_url: String,
    },
    /// Install an app, including setting modifiers and role overrides from a `joining-service-join` output.
    InstallHapp {
        #[clap(long)]
        admin_ws: SocketAddr,

        #[clap(long)]
        admin_ws_origin: Option<String>,

        #[clap(long)]
        happ_path: PathBuf,

        #[clap(long)]
        existing_agent: AgentPubKeyB64,

        #[clap(long)]
        join_payload_path: PathBuf,

        #[clap(long)]
        installed_app_id: Option<InstalledAppId>,
    },
    /// Accepts base64 encoded data and connects to Lair to sign the byte content with the identified agent identity.
    LairSignBase64 {
        #[clap(long)]
        agent_pubkey: AgentPubKeyB64,

        #[arg(long)]
        passphrase: Option<String>,

        #[clap(long)]
        lair_url: String,

        #[clap(long, allow_hyphen_values = true)]
        data: String,
    },
    /// Calls the alliance, transactor zome's get_all_lane function
    CallGetAllLane {
        #[clap(long)]
        admin_ws: SocketAddr,

        #[clap(long)]
        installed_app_id: InstalledAppId,

        /// Lair passphrase for zome call signing.
        #[arg(long)]
        passphrase: Option<String>,

        #[clap(long)]
        lair_url: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::SeedBundle { passphrase } => {
            let pass_locked = read_passphrase(passphrase)?;

            let bundle = unytctl::create_seed_bundle(pass_locked).await?;

            let mut out = std::io::stdout();
            out.write_all(bundle.to_json()?.as_bytes())?;
            out.flush()?;
        }
        CliCommand::BareSigningKeypair => {
            let keypair = unytctl::create_bare_signing_keypair().await?;

            let mut out = std::io::stdout();
            out.write_all(keypair.to_json()?.as_bytes())?;
            out.flush()?;
        }
        CliCommand::JoiningServiceJoin {
            seed_bundle,
            seed_bundle_passphrase,
            joining_service_url,
        } => {
            let pass_locked = read_passphrase(seed_bundle_passphrase)?;

            let seed_bundle = std::fs::read_to_string(seed_bundle)?;

            let proofs =
                unytctl::joining_service_join(joining_service_url, seed_bundle, pass_locked)
                    .await?;

            let mut out = std::io::stdout();
            out.write_all(proofs.to_json()?.as_bytes())?;
            out.flush()?;
        }
        CliCommand::InstallHapp {
            admin_ws,
            admin_ws_origin,
            happ_path,
            existing_agent,
            join_payload_path,
            installed_app_id,
        } => {
            let app_info = unytctl::install_happ(
                admin_ws,
                admin_ws_origin,
                happ_path,
                existing_agent,
                join_payload_path,
                installed_app_id,
            )
            .await?;

            let mut out = std::io::stdout();
            out.write_all(app_info.to_json()?.as_bytes())?;
            out.flush()?;
        }
        CliCommand::LairSignBase64 {
            agent_pubkey,
            passphrase,
            lair_url,
            data,
        } => {
            let pass_locked = read_passphrase(passphrase)?;

            let signature =
                unytctl::lair_sign_base64(agent_pubkey, pass_locked, lair_url, data).await?;

            let mut out = std::io::stdout();
            out.write_all(signature.as_bytes())?;
            out.flush()?;
        }
        CliCommand::CallGetAllLane {
            admin_ws,
            installed_app_id,
            passphrase,
            lair_url,
        } => {
            let pass_locked = read_passphrase(passphrase)?;

            let lanes = unytctl::call_get_all_lane::<serde_json::Value>(
                admin_ws,
                installed_app_id,
                pass_locked,
                lair_url,
            )
            .await?;

            let mut out = std::io::stdout();
            out.write_all(serde_json::to_string_pretty(&lanes)?.as_bytes())?;
            out.flush()?;
        }
    };

    Ok(())
}

fn read_passphrase(passphrase: Option<String>) -> Result<SharedLockedArray, std::io::Error> {
    let pass = match passphrase {
        Some(passphrase) => passphrase,
        None => {
            if std::io::stdin().is_terminal() {
                rpassword::prompt_password("Enter passphrase: ")?
            } else {
                rpassword::read_password_with_config(
                    rpassword::ConfigBuilder::new()
                        .input_reader(std::io::stdin())
                        .output_discard()
                        .build(),
                )?
            }
        }
    };
    let pass = Zeroizing::new(pass);
    let pass_locked = LockedArray::from(pass.as_bytes().to_vec());
    Ok(Arc::new(Mutex::new(pass_locked)))
}
