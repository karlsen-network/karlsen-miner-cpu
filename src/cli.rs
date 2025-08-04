use crate::Error;
use clap::{ArgGroup, Parser};
use log::LevelFilter;
use std::{net::IpAddr, str::FromStr};

#[derive(Debug, Parser)]
#[clap(about, version, author)]
#[clap(group(ArgGroup::new("required")))]
pub struct Opt {
    #[clap(short, long, display_order = 3)]
    /// Enable debug logging level
    pub debug: bool,
    #[clap(short = 'a', long = "mining-address", display_order = 0)]
    /// The Karlsen address for the miner reward
    pub mining_address: String,
    #[clap(short = 's', long = "karlsend-address", default_value = "127.0.0.1", display_order = 1)]
    /// The IP of the karlsend instance
    pub karlsend_address: String,

    #[clap(long = "devfund", display_order = 7)]
    /// Mine a percentage of the blocks to the Karlsen devfund [default: Off]
    pub devfund_address: Option<String>,

    #[clap(long = "devfund-percent", default_value = "1", display_order = 8, value_parser = parse_devfund_percent)]
    /// The percentage of blocks to send to the devfund
    pub devfund_percent: u16,

    #[clap(short, long, display_order = 2)]
    /// Karlsend port [default: Mainnet = 42110, Testnet = 42210, Devnet = 42610]
    port: Option<u16>,

    #[clap(long, display_order = 4)]
    /// Use testnet instead of mainnet [default: false]
    testnet: bool,
    #[clap(long, display_order = 5)]
    /// Use devnet instead of mainnet [default: false]
    devnet: bool,
    #[clap(short = 't', long = "threads", display_order = 6)]
    /// Amount of miner threads to launch [default: number of logical cpus]
    pub num_threads: Option<u16>,
    #[clap(long = "mine-when-not-synced", display_order = 9)]
    /// Mine even when karlsend says it is not synced, only useful when passing `--enable-unsynced-mining` to karlsend  [default: false]
    pub mine_when_not_synced: bool,
    #[clap(long = "throttle", display_order = 10)]
    /// Throttle (milliseconds) between each pow hash generation (used for development testing)
    pub throttle: Option<u64>,
    #[clap(long, display_order = 11)]
    /// Output logs in alternative format (same as karlsend)
    pub altlogs: bool,
    #[clap(long = "no-full-dataset", display_order = 12)]
    /// Disable full dataset prebuilding (~4.6GB). Uses light cache only (~75MB). [default: false]
    pub no_full_dataset: bool,
    #[clap(long = "lazy-dataset", display_order = 13)]
    /// Lazily build the dataset on demand. Pre-allocates 4.6GB but only computes items when accessed. Requires --no-full-dataset to be false. [default: false]
    pub lazy_dataset: bool,
}

fn parse_devfund_percent(s: &str) -> Result<u16, &'static str> {
    let err = "devfund-percent should be --devfund-percent=XX.YY up to 2 numbers after the dot";
    let mut splited = s.split('.');
    let prefix = splited.next().ok_or(err)?;
    // if there's no postfix then it's 0.
    let postfix = splited.next().ok_or(err).unwrap_or("0");
    // error if there's more than a single dot
    if splited.next().is_some() {
        return Err(err);
    };
    // error if there are more than 2 numbers before or after the dot
    if prefix.len() > 2 || postfix.len() > 2 {
        return Err(err);
    }
    let postfix: u16 = postfix.parse().map_err(|_| err)?;
    let prefix: u16 = prefix.parse().map_err(|_| err)?;
    // can't be more than 99.99%,
    if prefix >= 100 || postfix >= 100 {
        return Err(err);
    }
    Ok(prefix * 100 + postfix)
}

impl Opt {
    pub fn process(&mut self) -> Result<(), Error> {
        if self.karlsend_address.is_empty() {
            self.karlsend_address = "127.0.0.1".to_string();
        }

        if !self.karlsend_address.starts_with("grpc://") {
            IpAddr::from_str(&self.karlsend_address)?;
            let port = self.port();
            self.karlsend_address = format!("grpc://{}:{}", self.karlsend_address, port);
        }
        log::info!("Karlsend address: {}", self.karlsend_address);

        Ok(())
    }

    fn port(&mut self) -> u16 {
        *self.port.get_or_insert(if self.devnet {
            42610
        } else if self.testnet {
            42210
        } else {
            42110
        })
    }

    pub fn log_level(&self) -> LevelFilter {
        if self.debug {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        }
    }
}
