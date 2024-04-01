#!/bin/bash
set -xe
export RUST_LOG=info
export RUST_BACKTRACE=full
 # --release
cargo r -- \
  --sk="0x24e196d2883a86132d43f793dd6ffd0c11a456afba1c1c3180674b6f0624cace" \
  --rpc="http://127.0.0.1:8545" \
  --btc-address="bcrt1qhwkqamxr93phyhlc82elqm2n8hufr8xls0djwn"
