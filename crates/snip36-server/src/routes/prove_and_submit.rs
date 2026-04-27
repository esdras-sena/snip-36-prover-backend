use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use starknet_types_core::felt::Felt;
use tokio::io::AsyncBufReadExt;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use snip36_core::proof::parse_proof_facts_json;
use snip36_core::signing::{compute_invoke_v3_tx_hash, felt_from_hex, sign, sign_and_build_payload};
use snip36_core::types::{ResourceBounds, SubmitParams, STRK_TOKEN};

use crate::routes::prove_block::find_snip36_bin;
use crate::state::AppState;

use super::fund::error_response;

#[derive(Deserialize)]
pub struct ProveAndSubmitRequest {
    /// Unsigned invoke v3 transaction. Required: `calldata`, `nonce`.
    /// `sender_address` is required when `private_key` is supplied; otherwise
    /// the server uses its env account address. The server fills in
    /// `resource_bounds` from live gas prices and uses defaults for the
    /// remaining v3 fields (tip 0, L1 DA modes, empty paymaster_data and
    /// account_deployment_data).
    pub unsigned_tx: serde_json::Value,
    /// Reference block to prove against. Defaults to latest-1 if omitted.
    pub block_number: Option<u64>,
    /// Optional signer key (hex). When omitted, the server falls back to the
    /// private key configured in env and sets sender to the env account
    /// address.
    pub private_key: Option<String>,
}

/// POST /api/prove-and-submit
///
/// SNIP-36 cycle for a client-provided unsigned tx, in this order:
///   1. receive unsigned invoke v3 tx (sender + calldata + nonce)
///   2. sign the standard hash with master key, run in virtual OS against
///      `block_number` -> proof + proof_facts
///   3. wrap the same calldata + nonce with proof_facts, re-sign with master key
///   4. submit via `starknet_addInvokeTransaction`
///
/// Streams progress as SSE.
pub async fn prove_and_submit(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProveAndSubmitRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let unsigned_tx = req.unsigned_tx;

    // Resolve signer: if the request provided a private key, use it together
    // with the request's sender_address. Otherwise fall back to the env-
    // configured master key and force sender = env account address.
    let (private_key_hex, sender_hex) = match req.private_key.as_deref() {
        Some(pk) => {
            let sender = unsigned_tx
                .get("sender_address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    error_response(
                        StatusCode::BAD_REQUEST,
                        "sender_address is required when private_key is supplied",
                    )
                })?
                .to_string();
            (pk.to_string(), sender)
        }
        None => (
            state.config.private_key.clone(),
            state.config.account_address.clone(),
        ),
    };
    let private_key_felt = felt_from_hex(&private_key_hex)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("private_key: {e}")))?;
    let sender_felt = felt_from_hex(&sender_hex)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("sender_address: {e}")))?;

    let calldata_hex: Vec<String> = unsigned_tx
        .get("calldata")
        .and_then(|v| v.as_array())
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "missing calldata array"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(String::from)
                .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "calldata entry not string"))
        })
        .collect::<Result<_, _>>()?;
    let calldata_felts: Vec<Felt> = calldata_hex
        .iter()
        .map(|h| felt_from_hex(h))
        .collect::<Result<_, _>>()
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("calldata: {e}")))?;

    let nonce_hex = unsigned_tx
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "missing nonce"))?
        .to_string();
    let nonce_felt = felt_from_hex(&nonce_hex)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("nonce: {e}")))?;

    let chain_id = state
        .config
        .chain_id_felt()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let reference_block = match req.block_number {
        Some(b) => b,
        None => {
            let latest = state
                .rpc
                .block_number()
                .await
                .map_err(|e| error_response(StatusCode::BAD_GATEWAY, &e.to_string()))?;
            latest.checked_sub(1).ok_or_else(|| {
                error_response(StatusCode::BAD_REQUEST, "chain has no block before latest")
            })?
        }
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(64);
    let state_clone = Arc::clone(&state);

    tokio::spawn(async move {
        let state = state_clone;

        let send = |event: &str, data: String| {
            let tx = tx.clone();
            let event = event.to_string();
            async move {
                let _ = tx.send(Ok(Event::default().event(event).data(data))).await;
            }
        };

        // -- Phase 1: sign the unsigned tx with the master key --
        send("phase", "signing".to_string()).await;
        send(
            "log",
            format!(
                "Received unsigned tx (nonce {nonce_hex}, {} calldata felts), reference block {reference_block}",
                calldata_felts.len()
            ),
        )
        .await;

        let resource_bounds_for_vos: ResourceBounds = match state.rpc.resource_bounds().await {
            Ok(rb) => rb,
            Err(e) => {
                send("error", format!("Failed to fetch gas prices: {e}")).await;
                return;
            }
        };

        let standard_tx_hash = compute_invoke_v3_tx_hash(
            sender_felt,
            &calldata_felts,
            chain_id,
            nonce_felt,
            Felt::ZERO,
            &resource_bounds_for_vos,
            &[],
            &[],
            0,
            0,
            &[], // proof_facts empty for the standard hash
        );
        let sig = match sign(private_key_felt, standard_tx_hash) {
            Ok(s) => s,
            Err(e) => {
                send("error", format!("Standard signing failed: {e}")).await;
                return;
            }
        };

        // Build the signed v3 invoke JSON the prover expects.
        let signed_tx_json = serde_json::json!({
            "type": "INVOKE",
            "version": "0x3",
            "sender_address": sender_hex,
            "calldata": calldata_hex,
            "nonce": nonce_hex,
            "resource_bounds": resource_bounds_for_vos.to_rpc_json(),
            "tip": "0x0",
            "paymaster_data": [],
            "account_deployment_data": [],
            "nonce_data_availability_mode": "L1",
            "fee_data_availability_mode": "L1",
            "signature": [format!("{:#x}", sig.r), format!("{:#x}", sig.s)],
        });

        let job_id = Uuid::new_v4();
        let output_dir = state.config.output_dir.join("prove-and-submit");
        if let Err(e) = tokio::fs::create_dir_all(&output_dir).await {
            send("error", format!("Failed to create output dir: {e}")).await;
            return;
        }
        let tx_path = output_dir.join(format!("{job_id}_tx.json"));
        let proof_path = output_dir.join(format!("{job_id}.proof"));

        let tx_json_pretty = match serde_json::to_string_pretty(&signed_tx_json) {
            Ok(s) => s,
            Err(e) => {
                send("error", format!("Failed to serialize tx: {e}")).await;
                return;
            }
        };
        if let Err(e) = tokio::fs::write(&tx_path, tx_json_pretty).await {
            send("error", format!("Failed to write tx JSON: {e}")).await;
            return;
        }

        // -- Phase 2: run virtual OS --
        send("phase", "proving".to_string()).await;
        send(
            "log",
            format!("Running virtual OS against block {reference_block}..."),
        )
        .await;

        let snip36_bin = find_snip36_bin();
        let mut prove_args = vec![
            "prove".to_string(),
            "virtual-os".to_string(),
            "--block-number".to_string(),
            reference_block.to_string(),
            "--tx-json".to_string(),
            tx_path.to_string_lossy().to_string(),
            "--rpc-url".to_string(),
            state.config.rpc_url.clone(),
            "--output".to_string(),
            proof_path.to_string_lossy().to_string(),
            "--strk-fee-token".to_string(),
            STRK_TOKEN.to_string(),
        ];
        if let Ok(prover_url) = std::env::var("PROVER_URL") {
            if !prover_url.is_empty() {
                prove_args.push("--prover-url".to_string());
                prove_args.push(prover_url);
            }
        }

        let child = tokio::process::Command::new(&snip36_bin)
            .args(&prove_args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                send(
                    "error",
                    format!("Failed to spawn prover ({}): {e}", snip36_bin.display()),
                )
                .await;
                return;
            }
        };

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let tx_stdout = tx.clone();
        let stdout_handle = tokio::spawn(async move {
            if let Some(stdout) = stdout {
                let reader = tokio::io::BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if !line.is_empty() {
                        let _ = tx_stdout
                            .send(Ok(Event::default().event("log").data(line)))
                            .await;
                    }
                }
            }
        });
        let tx_stderr = tx.clone();
        let stderr_handle = tokio::spawn(async move {
            if let Some(stderr) = stderr {
                let reader = tokio::io::BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if !line.is_empty() {
                        let _ = tx_stderr
                            .send(Ok(Event::default().event("log").data(line)))
                            .await;
                    }
                }
            }
        });
        let _ = stdout_handle.await;
        let _ = stderr_handle.await;
        let status = child.wait().await;

        if !status.map(|s| s.success()).unwrap_or(false) || !proof_path.exists() {
            send("error", "Proof generation failed".to_string()).await;
            return;
        }

        let proof_size = tokio::fs::metadata(&proof_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        send("log", format!("Proof generated ({proof_size} bytes)")).await;

        // -- Phase 3: read proof + proof_facts --
        let proof_b64 = match tokio::fs::read_to_string(&proof_path).await {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                send("error", format!("Failed to read proof: {e}")).await;
                return;
            }
        };
        let proof_facts_path = proof_path.with_extension("proof_facts");
        let proof_facts_str = match tokio::fs::read_to_string(&proof_facts_path).await {
            Ok(s) => s,
            Err(e) => {
                send("error", format!("Failed to read proof_facts: {e}")).await;
                return;
            }
        };
        let proof_facts_hex = match parse_proof_facts_json(&proof_facts_str) {
            Ok(f) => f,
            Err(e) => {
                send("error", format!("Invalid proof_facts: {e}")).await;
                return;
            }
        };
        let proof_facts: Vec<Felt> = match proof_facts_hex
            .iter()
            .map(|h| felt_from_hex(h))
            .collect::<Result<_, _>>()
        {
            Ok(f) => f,
            Err(e) => {
                send("error", format!("Failed to parse proof_facts: {e}")).await;
                return;
            }
        };

        // -- Phase 4: re-sign with proof_facts and submit --
        send("phase", "submitting".to_string()).await;
        let resource_bounds_for_submit = match state.rpc.resource_bounds().await {
            Ok(rb) => rb,
            Err(e) => {
                send("error", format!("Failed to fetch gas prices: {e}")).await;
                return;
            }
        };

        let params = SubmitParams {
            sender_address: sender_felt,
            private_key: private_key_felt,
            calldata: calldata_felts,
            proof_base64: proof_b64,
            proof_facts,
            nonce: nonce_felt,
            chain_id,
            resource_bounds: resource_bounds_for_submit,
        };
        let (local_tx_hash, invoke_tx) = match sign_and_build_payload(&params) {
            Ok(r) => r,
            Err(e) => {
                send("error", format!("SNIP-36 signing failed: {e}")).await;
                return;
            }
        };
        let local_tx_hash_hex = format!("{local_tx_hash:#x}");
        send(
            "log",
            format!("Submitting wrapped tx {local_tx_hash_hex} via RPC..."),
        )
        .await;

        let rpc_tx_hash = match state.rpc.add_invoke_transaction(invoke_tx).await {
            Ok(h) => h,
            Err(e) => {
                send("error", format!("RPC submission failed: {e}")).await;
                return;
            }
        };

        send(
            "complete",
            serde_json::json!({
                "tx_hash": rpc_tx_hash,
                "local_tx_hash": local_tx_hash_hex,
                "reference_block": reference_block,
                "proof_size": proof_size,
                "proof_file": proof_path.to_string_lossy(),
            })
            .to_string(),
        )
        .await;
    });

    Ok(Sse::new(ReceiverStream::new(rx)))
}
