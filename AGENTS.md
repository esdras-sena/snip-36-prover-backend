# AGENTS.md

## Project Overview

SNIP-36 virtual block proving tooling for Starknet. Two-phase pipeline:
1. **Execute** — Run virtual OS against RPC node → produces Cairo PIE
2. **Prove** — Feed PIE through bootloader into stwo prover → produces stwo proof

## Architecture

- `scripts/` — Bash scripts orchestrating the pipeline (setup, prove, extract, run)
- `extractor/` — Rust crate that extracts the compiled virtual OS program from `apollo_starknet_os_program`
- `tests/` — E2E test, contract artifacts, signing/submission tooling (Python + Bash)
- `sample-input/` — Template inputs for the prover and bootloader
- `deps/` — (generated, gitignored) Cloned repos: `proving-utils`, `sequencer`

## Key Conventions

- Shell scripts use `set -euo pipefail` and are in `scripts/`
- Rust code targets `nightly-2025-07-14` (pinned by stwo 2.1.0)
- Python scripts (`tests/sign-and-submit.py`, `tests/convert-proof.py`) use starknet-py
- All proof output is in cairo-serde JSON format (hex field element array)
- Proofs and build artifacts go in `output/` (gitignored)

## Building

```bash
./scripts/setup.sh           # Clone deps, build stwo prover
cargo build -p virtual-os-extractor  # Build extractor
```

## Testing

```bash
./scripts/test-pipeline.sh   # Sanity check: prove + verify a test program
./tests/e2e-test.sh          # Full E2E: execute → prove → sign → submit
```

## Environment

- `.env` contains secrets (RPC URL, private key) — never commit
- `.env.example` shows required variables
- Target network: Starknet Integration Sepolia

## Working with Proofs

- PIE files: `.pie.zip` — Cairo Program Independent Execution artifacts
- Proof files: `.proof` — stwo proofs in cairo-serde format
- The `proof_facts` field in INVOKE_TXN_V3 must be included in Poseidon tx hash computation (non-standard — see `tests/sign-and-submit.py`)

## Common Pitfalls

- Runner must use `--prefetch-state false` (prefetch has a bug with missing storage keys)
- Tx signing must include `proof_facts` in the hash chain — standard starknet-py does NOT do this
- L2 gas for proof verification is ~75M — set max to ≥117M
