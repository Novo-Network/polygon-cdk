use anyhow::Result;
use clap::Parser;

use crate::deploy::Deploy;

#[derive(Debug, Parser)]
pub struct CommandLine {
    #[clap(short, long)]
    rpc: String,

    #[clap(long)]
    sk: String,

    #[clap(short, long)]
    btc_address: String,

    #[clap(long)]
    salt: String,
}

impl CommandLine {
    pub async fn execute(self) -> Result<()> {
        let deploy = Deploy::new(&self.rpc, &self.sk, &self.salt).await?;
        deploy.run(&self.btc_address).await
    }
}
