#![cfg_attr(all(test, feature = "bench"), feature(test))]

use chrono::Local;
use clap::Parser;
use log::{info, warn};
use std::error::Error as StdError;
use std::{
    io::Write,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    cli::Opt, client::KarlsendHandler, miner::MinerManager, proto::NotifyNewBlockTemplateRequestMessage,
    proto::RpcNotifyCommand, target::Uint256,
};

mod cli;
mod client;
mod karlsend_messages;
mod miner;
mod pow;
mod swap_rust;
mod target;

pub mod proto {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("protowire");
}

pub type Error = Box<dyn StdError + Send + Sync + 'static>;

type Hash = Uint256;

#[derive(Debug, Clone)]
pub struct ShutdownHandler(Arc<AtomicBool>);

pub struct ShutdownOnDrop(ShutdownHandler);

impl ShutdownHandler {
    #[inline(always)]
    pub fn is_shutdown(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    #[inline(always)]
    pub fn arm(&self) -> ShutdownOnDrop {
        ShutdownOnDrop(self.clone())
    }
}

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.0 .0.store(true, Ordering::Release);
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut opt: Opt = Opt::parse();
    opt.process()?;

    let mut builder = env_logger::builder();
    builder.filter_level(opt.log_level()).parse_default_env();
    if opt.altlogs {
        builder.format(|buf, record| {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f%:z");
            writeln!(buf, "{} [{:>5}] {}", timestamp, record.level(), record.args())
        });
    }
    builder.init();

    let throttle = opt.throttle.map(Duration::from_millis);
    let shutdown = ShutdownHandler(Arc::new(AtomicBool::new(false)));
    let _shutdown_when_dropped = shutdown.arm();

    while !shutdown.is_shutdown() {
        match KarlsendHandler::connect(
            opt.karlsend_address.clone(),
            opt.mining_address.clone(),
            opt.mine_when_not_synced,
        )
        .await
        {
            Ok(mut client) => {
                let mut miner_manager = MinerManager::new(
                    client.send_channel.clone(),
                    opt.num_threads,
                    throttle,
                    shutdown.clone(),
                    opt.mine_when_not_synced,
                    !opt.no_full_dataset,
                    opt.lazy_dataset,
                );
                if let Some(devfund_address) = &opt.devfund_address {
                    client.add_devfund(devfund_address.clone(), opt.devfund_percent);
                    info!(
                        "devfund enabled, mining {}.{}% of the time to devfund address: {} ",
                        opt.devfund_percent / 100,
                        opt.devfund_percent % 100,
                        devfund_address
                    );
                }
                if let Err(e) = client
                    .client_send(NotifyNewBlockTemplateRequestMessage { command: RpcNotifyCommand::NotifyStart as i32 })
                    .await
                {
                    warn!("Error sending block template request: {}", e);
                }
                if let Err(e) = client.client_get_block_template().await {
                    warn!("Error getting block template: {}", e);
                }
                if let Err(e) = client.listen(&mut miner_manager, shutdown.clone()).await {
                    warn!("Disconnected from karlsend: {}. Retrying", e);
                }
            }
            Err(e) => {
                warn!("Failed to connect to karlsend: {}. Retrying in 10 seconds...", e);
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    Ok(())
}
