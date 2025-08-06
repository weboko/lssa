use anyhow::Result;
use clap::Parser;
use node_core::{execute_subcommand, Args};
use tokio::runtime::Builder;

pub const NUM_THREADS: usize = 2;

fn main() -> Result<()> {
    let runtime = Builder::new_multi_thread()
        .worker_threads(NUM_THREADS)
        .enable_all()
        .build()
        .unwrap();

    let args = Args::parse();

    runtime.block_on(async move {
        execute_subcommand(args.command).await.unwrap();
    });

    Ok(())
}
