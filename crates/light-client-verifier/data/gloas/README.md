# Fulu -> Gloas fixtures

Captured from the ethereum devnet of cosmos-ethereum-ibc-lcp (`tests/e2e/chains/ethereum`,
Glamsterdam-capable geth/lodestar images) started with `make network EPOCH_LATEST_HF=8`:
minimal preset, every fork at epoch 0 except Gloas at epoch 8, which is the first slot of
sync committee period 1.

| file | source |
|---|---|
| `bootstrap_period_0.json` | `/eth/v1/beacon/light_client/bootstrap/{root of period 0 finalized header}` |
| `light_client_update_period_{0,1}.json` | `/eth/v1/beacon/light_client/updates?start_period=0&count=2` |
| `finality_update_gloas.json` | `/eth/v1/beacon/light_client/finality_update` once finality passed the fork |
| `light_client_update_period_1_rlp.json` | `debug_getRawHeader` / `eth_getBlockByHash` of the period 1 finalized `execution_block_hash` |

Used by `test_fork_fulu_to_gloas` in `src/consensus.rs`.
