# karlsen-miner-cpu

[![Build Status](https://github.com/karlsen-network/karlsen-miner-cpu/actions/workflows/ci.yaml/badge.svg)](https://github.com/karlsen-network/karlsen-miner-cpu/actions/workflows/ci.yaml)
[![GitHub release](https://img.shields.io/github/v/release/karlsen-network/karlsen-miner-cpu.svg)](https://github.com/karlsen-network/karlsen-miner-cpu/releases)
[![GitHub downloads](https://img.shields.io/github/downloads/karlsen-network/karlsen-miner-cpu/total.svg)](https://github.com/karlsen-network/karlsen-miner-cpu/releases)
[![Join the Karlsen Discord Server](https://img.shields.io/discord/1169939685280337930.svg?label=&logo=discord&logoColor=ffffff)](https://discord.gg/ZPZRvgMJDT)

This is a reference cpu miner for mining karlsenhashv2. 

## Installation

### From Git Sources

If you are looking to build from the repository (for debug / extension), note that the plugins are additional
packages in the workspace. To compile a specific package, you run the following command or any subset of it

```sh
git clone https://github.com/karlsen-network/karlsen-miner-cpu.git
cd karlsen-miner-cpu
cargo build --release
```
And, the miner will be in `targets/release`.

# Usage
To start mining, you need to run [rusty-karlsen](https://github.com/karlsen-network/rusty-karlsen) and have an address to send the rewards to.
Here is a [guidance](https://github.com/karlsen-network/docs/blob/main/Getting%20Started/Rust%20Full%20Node%20Installation.md) on how to run a full node and how to generate addresses.

Help:
```
karlsen-miner 
A Karlsen high performance CPU miner

Usage: karlsen-miner.exe [OPTIONS] --mining-address <MINING_ADDRESS>

Options:
  -a, --mining-address <MINING_ADDRESS>
          The Karlsen address for the miner reward
  -s, --karlsend-address <KARLSEND_ADDRESS>
          The IP of the karlsend instance [default: 127.0.0.1]
  -p, --port <PORT>
          Karlsend port [default: Mainnet = 42110, Testnet = 42210, Devnet = 42610]
  -d, --debug
          Enable debug logging level
      --testnet
          Use testnet instead of mainnet [default: false]
      --devnet
          Use devnet instead of mainnet [default: false]
  -t, --threads <NUM_THREADS>
          Amount of miner threads to launch [default: number of logical cpus]
      --devfund <DEVFUND_ADDRESS>
          Mine a percentage of the blocks to the Karlsen devfund [default: Off]
      --devfund-percent <DEVFUND_PERCENT>
          The percentage of blocks to send to the devfund [default: 1]
      --mine-when-not-synced
          Mine even when karlsend says it is not synced, only useful when passing `--enable-unsynced-mining` to karlsend  [default: false]
      --throttle <THROTTLE>
          Throttle (milliseconds) between each pow hash generation (used for development testing)
      --altlogs
          Output logs in alternative format (same as karlsend)
      --no-full-dataset
          Disable full dataset prebuilding (~4.6GB). Uses light cache only (~75MB). [default: false]
  -h, --help
          Print help
  -V, --version
          Print version
```

To start mining, you just need to run the following:
```
./karlsen-miner --mining-address karlsen:XXXXX
```
