use anyhow::Result;
use clap::Parser;
use ethers::types::H160;

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

    #[clap(short, long)]
    chain_id: u64,

    #[clap(short, long)]
    fork_id: u64,

    #[clap(short, long)]
    min_delay: u64,

    #[clap(short, long)]
    timelock_address: H160,
}

impl CommandLine {
    pub async fn execute(self) -> Result<()> {
        let deploy = Deploy::new(
            &self.rpc,
            &self.sk,
            &self.salt,
            self.chain_id,
            self.fork_id,
            self.min_delay,
            self.timelock_address,
        )
        .await?;
        deploy.run(&self.btc_address).await
    }
}
