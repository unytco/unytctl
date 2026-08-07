use std::io::Write;
use std::sync::{Arc, Mutex};
use clap::{Parser, Subcommand};
use hc_seed_bundle::dependencies::sodoken::LockedArray;

#[derive(Parser, Debug)]
pub struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand, Debug)]
pub enum CliCommand {
    Progenitor {}
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Progenitor {} => {
            let pass = rpassword::prompt_password("Enter passphrase: ")?;
            let pass_locked = LockedArray::from(pass.as_bytes().to_vec());

            let bundle = unytctl::create_progenitor(Arc::new(Mutex::new(pass_locked))).await?;

            let mut out = std::io::stdout();
            out.write_all(bundle.to_json()?.as_bytes())?;
            out.flush()?;
        }
    };

    Ok(())
}
