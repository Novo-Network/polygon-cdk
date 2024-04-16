mod command_line;
mod contracts;
mod deploy;
mod utils;

use anyhow::Result;
use clap::Parser;
use command_line::CommandLine;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cmd = CommandLine::parse();
    cmd.execute().await
}
