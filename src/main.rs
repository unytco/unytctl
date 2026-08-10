use clap::{Parser, Subcommand};
use hc_seed_bundle::dependencies::sodoken::LockedArray;
use std::io::Write;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
pub struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand, Debug)]
pub enum CliCommand {
    Progenitor {
        #[arg(long)]
        passphrase: Option<String>,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Progenitor { passphrase } => {
            let pass = match passphrase {
                Some(passphrase) => passphrase,
                None => {
                    rpassword::prompt_password("Enter passphrase: ")?
                }
            };
            let pass = Zeroizing::new(pass);
            let pass_locked = LockedArray::from(pass.as_bytes().to_vec());

            let bundle = unytctl::create_progenitor(Arc::new(Mutex::new(pass_locked))).await?;

            let mut out = std::io::stdout();
            out.write_all(bundle.to_json()?.as_bytes())?;
            out.flush()?;
        }
    };

    Ok(())
}
