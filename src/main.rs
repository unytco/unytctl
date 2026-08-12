use clap::{Parser, Subcommand};
use hc_seed_bundle::dependencies::sodoken::LockedArray;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use hc_seed_bundle::SharedLockedArray;
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
    BareSigningKeypair {

    },
    /// Generate a membrane proof by bootstrapping the joining service for a given progenitor.
    MembraneProof {
        #[clap(long)]
        seed_bundle: PathBuf,

        #[clap(long)]
        seed_bundle_passphrase: Option<String>,

        #[clap(long)]
        joining_service_url: String,
    }
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
        CliCommand::BareSigningKeypair { } => {
            let keypair = unytctl::create_bare_signing_keypair().await?;

            let mut out = std::io::stdout();
            out.write_all(keypair.to_json()?.as_bytes())?;
            out.flush()?;
        }
        CliCommand::MembraneProof { seed_bundle, seed_bundle_passphrase, joining_service_url } => {
            let pass_locked = read_passphrase(seed_bundle_passphrase)?;

            let seed_bundle = std::fs::read_to_string(seed_bundle)?;

            let proofs = unytctl::create_membrane_proof(joining_service_url, seed_bundle, pass_locked).await?;

            let mut out = std::io::stdout();
            out.write_all(proofs.to_json()?.as_bytes())?;
            out.flush()?;
        }
    };

    Ok(())
}

fn read_passphrase(passphrase: Option<String>) -> Result<SharedLockedArray, std::io::Error> {
    let pass = match passphrase {
        Some(passphrase) => passphrase,
        None => {
            rpassword::prompt_password("Enter passphrase: ")?
        }
    };
    let pass = Zeroizing::new(pass);
    let pass_locked = LockedArray::from(pass.as_bytes().to_vec());
    Ok(Arc::new(Mutex::new(pass_locked)))
}
