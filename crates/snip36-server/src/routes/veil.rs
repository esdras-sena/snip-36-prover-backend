//! Veil prove-and-settle entry point.
//!
//! Veil splits every privacy operation into two halves (see veil_contracts):
//!   * `*_derive(...)` — takes the PRIVATE inputs (viewing keys, ephemeral
//!     secrets, salts, plaintext addresses). Runs OFF-CHAIN in the SNIP-36
//!     virtual OS. It computes the encrypted/derived public outputs and emits
//!     them as a single L2->L1 message via `send_message_to_l1_syscall`. The
//!     Poseidon hash of that message lands in `proof_facts.l1l2_message_hashes`.
//!   * `*_settle(...)` — takes only the derived public outputs. Runs ON-CHAIN.
//!     It calls `read_verified_proof_facts()` (asserting the proof's program
//!     hash equals `VEIL_DERIVE_PROGRAM_HASH`) and `message_in_facts(...)` to
//!     confirm its calldata was produced by the proven derive, then commits
//!     state.
//!
//! This route runs the full cycle for one operation:
//!   1. wrap `derive_calldata` in an `__execute__` call to `*_derive`
//!   2. sign + prove it in the virtual OS -> proof, proof_facts, L2->L1 message
//!   3. read the message payload, assemble the `*_settle` calldata from it
//!      (plus the original derive inputs / caller-supplied extras)
//!   4. wrap settle in an `__execute__` call, re-sign WITH proof_facts, and
//!      submit via the sequencer gateway carrying the derive's proof.
//!
//! The derive is a zero-fee transaction: the ERC-3643 pool refuses any other,
//! as StarkWare's pool does, so a derive only ever runs inside a proof.
//!
//! The settle calldata is assembled per-operation from a declarative source
//! table: each settle felt is taken either from the proven L2->L1 message
//! payload (`Src::Msg`), the original derive calldata (`Src::Derive`), or a
//! caller-supplied extra (`Src::Extra`, used only by withdraw's `recipient`).

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use starknet_types_core::felt::Felt;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use snip36_core::proof::parse_proof_facts_json;
use snip36_core::signing::{
    compute_invoke_v3_tx_hash, felt_from_hex, sign, sign_and_build_payload,
};
use snip36_core::types::{ResourceBounds, SubmitParams, STRK_TOKEN};

use crate::routes::prove_block::find_snip36_bin;
use crate::state::AppState;

use super::fund::error_response;

/// Where settle-calldata felts come from.
enum Src {
    /// One felt: index into the proven L2->L1 message payload emitted by `*_derive`.
    Msg(usize),
    /// One felt: index into the original `derive_calldata` (public inputs the client sent).
    Derive(usize),
    /// One felt: index into the caller-supplied `settle_extra` array (settle-only
    /// inputs not present in the derive call or the message — e.g. NFT withdraw
    /// recipient).
    Extra(usize),
    /// Many felts: the rest of the proven message payload from `start` onward,
    /// copied verbatim. Used by pools whose `*_settle` calldata equals the
    /// derive's emitted message (so `MsgRest(0)` = the whole message), which also
    /// carries a trailing variable-length `Array<felt252>` (count + elements) —
    /// e.g. the ERC-3643 pool's nullifier list.
    MsgRest(usize),
    /// Many felts: the rest of the caller-supplied `settle_extra` from `start`
    /// onward, copied verbatim. For a settle whose calldata is the proven
    /// message PLUS a variable-length tail the proof binds by HASH rather than
    /// by value — the ERC-3643 pool's `invoke_settle`, whose adapter calldata is
    /// checked against `msg.calldata_hash` on-chain. The tail must arrive as a
    /// serialized `Array<felt252>` (count, then elements).
    ExtraRest(usize),
}

struct OpSpec {
    derive_selector: &'static str,
    settle_selector: &'static str,
    /// One entry per settle-calldata felt, in serialized parameter order.
    settle_sources: Vec<Src>,
}

/// Resolve the op spec for a (pool, operation) pair. The two Veil pools share
/// function names (hence selectors) but emit different message layouts, so the
/// settle-assembly tables differ — they must be keyed by pool, not operation
/// alone. `pool` defaults to "erc721" for backward compatibility.
fn op_spec(pool: &str, operation: &str) -> Option<OpSpec> {
    match pool {
        "erc3643" => op_spec_erc3643(operation),
        "erc721" => op_spec_erc721(operation),
        _ => None,
    }
}

/// Multi-asset ERC-3643 pool (veil_contracts/src/VeilERC3643.cairo).
///
/// That contract was written so each `*_settle`'s ABI-serialized calldata equals
/// the `*_derive`'s emitted L2->L1 message VERBATIM (settle params mirror the
/// message field order, with the variable-length nullifier `Array<felt252>`
/// last). So the settle calldata is simply the whole proven message —
/// `MsgRest(0)` — which also handles the variable nullifier array with no
/// per-length bookkeeping. Selectors are shared with the NFT pool for
/// same-named functions; `forced_transfer` is ERC-3643-only.
fn op_spec_erc3643(operation: &str) -> Option<OpSpec> {
    use Src::*;
    let (derive_selector, settle_selector) = match operation {
        "register_viewing_key" => (
            "0x39027003009b51a342d76df8e9578ad63fa066abf1ace254cef86f608a413f7",
            "0x174b586a565540c6ee6961453732432418c0919dd8996e5cc23e0827e68ab7d",
        ),
        "deposit" => (
            "0x2c66df8f669ca27a004c5beaeefba37e0ffb7fd1e1cac1df9d6b77971b4d73b",
            "0xc4469bf25e061b0ade4a0e9feabb2a1c3b42e9d9ac03ab3daf6308e9504380",
        ),
        "private_transfer" => (
            "0x2a8e44dce9ab1af3aad36745112822d9bda8b0af1568d0d2c4bfb7e8108a1dc",
            "0x85a96a0bf86ab90556322a550329f2abfdb992be213843ba5db47462bcee26",
        ),
        "withdraw" => (
            "0x84bb00d67beaca8206ebc7b55916305acf72cef951bacf87eee694e353d33c",
            "0x17f88c621898faf2afa63e760df775efead7502179bf0d60cd32754abcbd7f1",
        ),
        "forced_transfer" => (
            "0x2464e2436239f82a0e35397a6f25cd04e44c9694a4bcfc587ce1493c3468085",
            "0x25c36c2d52ac9a3b22a08dc95f33febf7db87e2cccaec76fabfbd9d08e4efd8",
        ),
        // Reserves an empty open note for a named adapter to fill later
        // (STRK20 §10.3). The message leads with the note owner encrypted to
        // the auditor (3 felts), never the address itself.
        "create_open_note" => (
            "0x24e5000911f61760657ebbdf40ffae360b424e47a1af3f8534c7893e2716ad8",
            "0x26bd767e2302b0554836b64442644a3c0a5b31ebaa701bf65283d8105ba0985",
        ),
        // Anonymous DvP (Veil-only; STRK20 has no equivalent).
        "post_order" => (
            "0x1ebe10255a0f4eae46d18fc0a790f607de574fb82576a2986f3ca48c922d72b",
            "0x36f6fe12babdde70aaea9b30578f6102491964a1a31d6694acde02a2d8c2995",
        ),
        "cancel_order" => (
            "0x3ee1186295030d15d9b7ab162a7818cf1b467918f3dd4605cd967d919e665c4",
            "0x208e14ae2babb286ee7830363c7ad292d20f5ff4a5d960b2ce311be12827838",
        ),
        // Proven by the exchange's own account: opens each maker's commitment
        // and runs the per-maker issuer checks. The message names no maker.
        "execute_batch" => (
            "0x947596e3aad6c5feb08b9e811b7faef1ef890480a3d08ce6dbf8e8584dbded",
            "0x2441629842f2e145a25831aeba2baf6410b7f5054833b16b0528189f98ecab6",
        ),
        // External venue (HyperVeil): proven by the exchange's own account like
        // a batch; applies pending venue receipts to the makers' receive notes.
        // `venue_fill_settle(msg: VenueFill)` takes the proven message verbatim.
        "venue_fill" => (
            "0x786b1ae69ce9d64b9bfa976a1ea2a0ecb7cc231b73f40c8d16f48ef6844f78",
            "0x3b50e5e369934aac23d985c1054dab9dfa5bb379644cdd6229641070e29bf4a",
        ),
        // One atomic hop through an allowlisted adapter (STRK20 §10.3.2). The
        // ONLY ERC-3643 operation whose settle calldata is not just the message:
        // `invoke_settle(msg, nullifiers, calldata)` takes the adapter calldata
        // as a trailing argument. The proof binds it by HASH
        // (`msg.calldata_hash`, checked on-chain before proof_facts is read), so
        // it travels in `settle_extra` rather than in the message.
        "invoke" => {
            return Some(OpSpec {
                derive_selector:
                    "0x307676e56eaf5629412c1228b00fa35801560a2e0047babebcd57b1ed47002c",
                settle_selector:
                    "0x12f098835eb7a4a2872e859be1ac0c1054ebacb78b12741f018a981493a6b83",
                settle_sources: vec![MsgRest(0), ExtraRest(0)],
            });
        }
        _ => return None,
    };
    Some(OpSpec {
        derive_selector,
        settle_selector,
        settle_sources: vec![MsgRest(0)],
    })
}

/// Per-operation derive/settle selectors and settle-calldata source tables for
/// the NFT pool (veil_contracts/src/Veil.cairo).
///
/// Selectors are `starknet_keccak(function_name)` (computed with starknet.js
/// `getSelectorFromName`). Source tables are derived by matching each
/// `*_settle` parameter against the `send_message_to_l1_syscall` payload in the
/// corresponding `*_derive`. u256 args occupy two consecutive felts (low, high).
fn op_spec_erc721(operation: &str) -> Option<OpSpec> {
    use Src::*;
    let spec = match operation {
        // register_viewing_key_derive(user, private_viewing_key:u256, audit_ephemeral_secret_r)
        // msg: [user, public_viewing_key, audit_ephemeral_key_x, encrypted_private_viewing_key]
        // settle(user, public_viewing_key, audit_ephemeral_key_x, encrypted_private_viewing_key)
        "register_viewing_key" => OpSpec {
            derive_selector: "0x39027003009b51a342d76df8e9578ad63fa066abf1ace254cef86f608a413f7",
            settle_selector: "0x174b586a565540c6ee6961453732432418c0919dd8996e5cc23e0827e68ab7d",
            settle_sources: vec![Msg(0), Msg(1), Msg(2), Msg(3)],
        },
        // approve_private_transfer:
        // msg(24): [encrypted_id, channel_marker, subchannel_marker, ephemeral_key_x,
        //   encrypted_channel_key, encrypted_sender, approval_id, encrypted_owner,
        //   encrypted_collection_approval, encrypted_note_id, encrypted_id, encrypted_secret,
        //   outgoing_index, outgoing_channel_id, encrypted_recipient, channel_outgoing_salt,
        //   subchannel_counts, subchannel_id, previous_subchannel_id,
        //   encrypted_collection_subchannel, subchannel_salt, approval_salt, recipient_index,
        //   recipient]
        // settle(encrypted_id, channel_marker, subchannel_marker, outgoing_index,
        //   outgoing_channel_id, encrypted_channel_key, encrypted_sender, ephemeral_key_x,
        //   encrypted_recipient, channel_outgoing_salt, subchannel_counts, subchannel_id,
        //   previous_subchannel_id, encrypted_collection_subchannel, recipient, recipient_index,
        //   subchannel_salt, approval_id, encrypted_owner, encrypted_collection_approval,
        //   encrypted_note_id, encrypted_secret, approval_salt)
        "approve_private_transfer" => OpSpec {
            derive_selector: "0x212d4c2b460679c5dd3ae8200e78ce2002fb2f392f7f8f7707883e226e893f3",
            settle_selector: "0x2609e1d5e49bac382129e6523faf32cee5ebfc89e49a10ba7a3cb6fa32626d7",
            settle_sources: vec![
                Msg(0), Msg(1), Msg(2), Msg(12), Msg(13), Msg(4), Msg(5), Msg(3), Msg(14),
                Msg(15), Msg(16), Msg(17), Msg(18), Msg(19), Msg(23), Msg(22), Msg(20), Msg(6),
                Msg(7), Msg(8), Msg(9), Msg(11), Msg(21),
            ],
        },
        // private_transfer_as_approved:
        // msg(21): [dest_note_id, dest_note_index, encrypted_id_dest, channel_marker,
        //   subchannel_marker, ephemeral_key_x, encrypted_channel_key, encrypted_sender,
        //   approval_id, outgoing_index, outgoing_channel_id, encrypted_recipient,
        //   channel_outgoing_salt, subchannel_counts, subchannel_id, previous_subchannel_id,
        //   encrypted_collection_subchannel, subchannel_salt, recipient_index, nullifier,
        //   recipient]
        // settle(note_id, encrypted_id, note_index, channel_marker, subchannel_marker,
        //   outgoing_index, outgoing_channel_id, encrypted_channel_key, encrypted_sender,
        //   ephemeral_key_x, encrypted_recipient, channel_outgoing_salt, subchannel_counts,
        //   subchannel_id, previous_subchannel_id, encrypted_collection_subchannel, recipient,
        //   recipient_index, subchannel_salt, nullifier, approval_id)
        "private_transfer_as_approved" => OpSpec {
            derive_selector: "0x3d1ed6c15dbee4dd67d8d60d9d798910e24c0162753375c2a3f6387b4b91db0",
            settle_selector: "0x2bb32a30f698634ae93f980e808a282896391e8dc03a54ad1a94f1ffe93cb70",
            settle_sources: vec![
                Msg(0), Msg(2), Msg(1), Msg(3), Msg(4), Msg(9), Msg(10), Msg(6), Msg(7), Msg(5),
                Msg(11), Msg(12), Msg(13), Msg(14), Msg(15), Msg(16), Msg(20), Msg(18), Msg(17),
                Msg(19), Msg(8),
            ],
        },
        // revoke_private_approval: msg(1): [approval_id]; settle(approval_id)
        "revoke_private_approval" => OpSpec {
            derive_selector: "0xf77e6b9b72e861dcd2e2bbc8535b7ce6b2ad4304131f2ef2b8998b83fed45a",
            settle_selector: "0x1662b464795b8dc8c6d000e50d3e4c5d8f753e77f6a3b2ecb6c44aa8475ce",
            settle_sources: vec![Msg(0)],
        },
        // private_transfer:
        // msg(20): [dest_note_id, encrypted_id, dest_note_index, channel_marker,
        //   subchannel_marker, outgoing_index, outgoing_channel_id, ephemeral_key_x,
        //   encrypted_channel_key, encrypted_sender, encrypted_recipient, channel_outgoing_salt,
        //   subchannel_counts, subchannel_id, previous_subchannel_id, encrypted_collection,
        //   subchannel_salt, nullifier, recipient_index, recipient]
        // settle(note_id, encrypted_id, note_index, channel_marker, subchannel_marker,
        //   outgoing_index, outgoing_channel_id, encrypted_channel_key, encrypted_sender,
        //   ephemeral_key_x, encrypted_recipient, channel_outgoing_salt, subchannel_counts,
        //   subchannel_id, previous_subchannel_id, encrypted_collection, recipient,
        //   recipient_index, subchannel_salt, nullifier)
        "private_transfer" => OpSpec {
            derive_selector: "0x2a8e44dce9ab1af3aad36745112822d9bda8b0af1568d0d2c4bfb7e8108a1dc",
            settle_selector: "0x85a96a0bf86ab90556322a550329f2abfdb992be213843ba5db47462bcee26",
            settle_sources: vec![
                Msg(0), Msg(1), Msg(2), Msg(3), Msg(4), Msg(5), Msg(6), Msg(8), Msg(9), Msg(7),
                Msg(10), Msg(11), Msg(12), Msg(13), Msg(14), Msg(15), Msg(19), Msg(18), Msg(16),
                Msg(17),
            ],
        },
        // deposit:
        // derive(collection, id:u256, owner, owner_private_viewing_key:u256,
        //   self_channel_ephemeral_secret_r, channel_outgoing_salt, salt:u128)
        //   -> owner is derive_calldata[3]
        // msg(21): [note_id, encrypted_id, note_index, channel_marker, subchannel_marker,
        //   collection, id.low, id.high, outgoing_index, outgoing_channel_id, ephemeral_key_x,
        //   encrypted_channel_key, encrypted_sender, encrypted_recipient, channel_outgoing_salt,
        //   subchannel_counts, subchannel_id, previous_subchannel_id, encrypted_collection,
        //   salt, recipient_index]
        // settle(collection, id:u256, note_id, encrypted_id, note_index, channel_marker,
        //   subchannel_marker, outgoing_index, outgoing_channel_id, encrypted_channel_key,
        //   encrypted_sender, ephemeral_key_x, encrypted_recipient, channel_outgoing_salt,
        //   subchannel_counts, subchannel_id, previous_subchannel_id, encrypted_collection,
        //   recipient_index, owner, subchannel_salt)
        "deposit" => OpSpec {
            derive_selector: "0x2c66df8f669ca27a004c5beaeefba37e0ffb7fd1e1cac1df9d6b77971b4d73b",
            settle_selector: "0xc4469bf25e061b0ade4a0e9feabb2a1c3b42e9d9ac03ab3daf6308e9504380",
            settle_sources: vec![
                Msg(5), Msg(6), Msg(7), Msg(0), Msg(1), Msg(2), Msg(3), Msg(4), Msg(8), Msg(9),
                Msg(11), Msg(12), Msg(10), Msg(13), Msg(14), Msg(15), Msg(16), Msg(17), Msg(18),
                Msg(20), Derive(3), Msg(19),
            ],
        },
        // withdraw:
        // msg(4): [nullifier, collection, id.low, id.high]
        // settle(nullifier, collection, id:u256, recipient)
        //   -> recipient is settle-only; caller supplies it via settle_extra[0]
        "withdraw" => OpSpec {
            derive_selector: "0x84bb00d67beaca8206ebc7b55916305acf72cef951bacf87eee694e353d33c",
            settle_selector: "0x17f88c621898faf2afa63e760df775efead7502179bf0d60cd32754abcbd7f1",
            settle_sources: vec![Msg(0), Msg(1), Msg(2), Msg(3), Extra(0)],
        },
        _ => return None,
    };
    Some(spec)
}

#[derive(Deserialize)]
pub struct VeilRequest {
    /// Which pool the operation targets: "erc721" (default) or "erc3643". The
    /// two pools share function names but emit different message layouts, so the
    /// settle assembly is keyed by pool.
    #[serde(default)]
    pub pool: Option<String>,
    /// NFT pool: register_viewing_key, approve_private_transfer,
    /// private_transfer_as_approved, revoke_private_approval, private_transfer,
    /// deposit, withdraw. ERC-3643 pool: register_viewing_key, deposit,
    /// create_open_note, invoke, private_transfer, withdraw, forced_transfer,
    /// post_order, cancel_order, execute_batch, venue_fill.
    pub operation: String,
    /// The Veil contract address (hex).
    pub veil_address: String,
    /// Serialized calldata for the `*_derive` function (hex felts, in ABI order).
    pub derive_calldata: Vec<String>,
    /// Settle-only inputs not present in the derive call or the proven message.
    /// Currently only `withdraw` uses this (recipient at index 0).
    #[serde(default)]
    pub settle_extra: Vec<String>,
    /// Reference block to prove against. Defaults to latest-SNIP36_BLOCK_LAG
    /// (3 by default) to absorb RPC-vs-gateway head skew.
    pub block_number: Option<u64>,
    /// Optional signer key (hex). When omitted, the server uses the env master
    /// key and forces sender = env account address.
    pub private_key: Option<String>,
    /// Sender account address (hex). Required when `private_key` is supplied;
    /// otherwise defaults to the env account address.
    pub sender_address: Option<String>,
    /// Sender nonce (hex). Required.
    pub nonce: String,
}

/// Build SNIP-6 `__execute__` calldata for a single call:
/// `[1, to, selector, calldata_len, ...calldata]`.
fn build_execute_calldata(to: Felt, selector: Felt, calldata: &[Felt]) -> Vec<Felt> {
    let mut out = Vec::with_capacity(4 + calldata.len());
    out.push(Felt::ONE); // one call
    out.push(to);
    out.push(selector);
    out.push(Felt::from(calldata.len()));
    out.extend_from_slice(calldata);
    out
}

/// POST /api/veil/prove-and-settle
///
/// Streams SSE progress for the derive-prove -> settle-submit cycle.
pub async fn veil_prove_and_settle(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VeilRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let pool = req.pool.as_deref().unwrap_or("erc721");
    let spec = op_spec(pool, &req.operation).ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            &format!("unknown pool/operation '{pool}'/'{}'", req.operation),
        )
    })?;

    let veil_address = felt_from_hex(&req.veil_address)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("veil_address: {e}")))?;
    let derive_selector = felt_from_hex(spec.derive_selector).expect("static selector hex");
    let settle_selector = felt_from_hex(spec.settle_selector).expect("static selector hex");

    let derive_calldata: Vec<Felt> = req
        .derive_calldata
        .iter()
        .map(|h| felt_from_hex(h))
        .collect::<Result<_, _>>()
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("derive_calldata: {e}")))?;
    let settle_extra: Vec<Felt> = req
        .settle_extra
        .iter()
        .map(|h| felt_from_hex(h))
        .collect::<Result<_, _>>()
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("settle_extra: {e}")))?;

    // Resolve signer: request key + sender, or env master key + env account.
    let (private_key_hex, sender_hex) = match req.private_key.as_deref() {
        Some(pk) => {
            let sender = req.sender_address.clone().ok_or_else(|| {
                error_response(
                    StatusCode::BAD_REQUEST,
                    "sender_address is required when private_key is supplied",
                )
            })?;
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
    let nonce_felt = felt_from_hex(&req.nonce)
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
            // The RPC and the sequencer gateway do not always agree on the head.
            // When the RPC is ahead, latest-1 can still be "too recent" for the
            // gateway, which rejects the settle with:
            //   "The proof block number N is too recent. The maximum allowed
            //    block number is N-1."
            // That wastes a full proof, so lag far enough to absorb the skew.
            // Overridable via SNIP36_BLOCK_LAG.
            let lag = std::env::var("SNIP36_BLOCK_LAG")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(3);
            latest.checked_sub(lag).ok_or_else(|| {
                error_response(StatusCode::BAD_REQUEST, "chain has no block before latest")
            })?
        }
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(64);
    let state_clone = Arc::clone(&state);
    let operation = req.operation.clone();

    tokio::spawn(async move {
        let state = state_clone;
        let send = |event: &str, data: String| {
            let tx = tx.clone();
            let event = event.to_string();
            async move {
                let _ = tx.send(Ok(Event::default().event(event).data(data))).await;
            }
        };

        // ── Phase 1: sign + prove the *_derive call in the virtual OS ──
        send("phase", "proving".to_string()).await;
        send(
            "log",
            format!(
                "Veil {operation}: proving *_derive ({} derive felts) against block {reference_block}",
                derive_calldata.len(),
            ),
        )
        .await;

        let derive_execute = build_execute_calldata(veil_address, derive_selector, &derive_calldata);
        let derive_calldata_hex: Vec<String> =
            derive_execute.iter().map(|f| format!("{f:#x}")).collect();

        // The virtual transaction carries no fee: the ERC-3643 pool's derives
        // refuse anything else, so they cannot run in a real block.
        let resource_bounds = ResourceBounds::zero_fee();

        // Standard hash: empty proof_facts (this is the tx that gets proven).
        let derive_tx_hash = compute_invoke_v3_tx_hash(
            sender_felt,
            &derive_execute,
            chain_id,
            nonce_felt,
            Felt::ZERO,
            &resource_bounds,
            &[],
            &[],
            0,
            0,
            &[],
        );
        let derive_sig = match sign(private_key_felt, derive_tx_hash) {
            Ok(s) => s,
            Err(e) => {
                send("error", format!("Derive signing failed: {e}")).await;
                return;
            }
        };

        let signed_derive_json = serde_json::json!({
            "type": "INVOKE",
            "version": "0x3",
            "sender_address": sender_hex,
            "calldata": derive_calldata_hex,
            "nonce": req.nonce,
            "resource_bounds": resource_bounds.to_rpc_json(),
            "tip": "0x0",
            "paymaster_data": [],
            "account_deployment_data": [],
            "nonce_data_availability_mode": "L1",
            "fee_data_availability_mode": "L1",
            "signature": [format!("{:#x}", derive_sig.r), format!("{:#x}", derive_sig.s)],
        });

        let job_id = Uuid::new_v4();
        let output_dir = state.config.output_dir.join("veil");
        if let Err(e) = tokio::fs::create_dir_all(&output_dir).await {
            send("error", format!("Failed to create output dir: {e}")).await;
            return;
        }
        let tx_path = output_dir.join(format!("{job_id}_derive.json"));
        let proof_path = output_dir.join(format!("{job_id}.proof"));

        let tx_json_pretty = match serde_json::to_string_pretty(&signed_derive_json) {
            Ok(s) => s,
            Err(e) => {
                send("error", format!("Failed to serialize derive tx: {e}")).await;
                return;
            }
        };
        if let Err(e) = tokio::fs::write(&tx_path, tx_json_pretty).await {
            send("error", format!("Failed to write derive tx JSON: {e}")).await;
            return;
        }

        let prove_start = std::time::Instant::now();
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

        // Admission control. One proof holds ~15.5 GB resident; running more at
        // once than memory allows does not just slow them down, it thrashes and
        // kills the proofs already in flight. Wait for a slot instead.
        // The permit is held for the whole proving subprocess and released on drop.
        let available = state.proof_slots.available_permits();
        if available == 0 {
            send(
                "phase",
                "queued: waiting for a proving slot".to_string(),
            )
            .await;
        }
        let _proof_permit = match state.proof_slots.clone().acquire_owned().await {
            Ok(p) => p,
            Err(e) => {
                send("error", format!("proving slots unavailable: {e}")).await;
                return;
            }
        };

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
        let tx_out = tx.clone();
        let h1 = tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            if let Some(stdout) = stdout {
                let mut lines = tokio::io::BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if !line.is_empty() {
                        let _ = tx_out.send(Ok(Event::default().event("log").data(line))).await;
                    }
                }
            }
        });
        let tx_err = tx.clone();
        let h2 = tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            if let Some(stderr) = stderr {
                let mut lines = tokio::io::BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if !line.is_empty() {
                        let _ = tx_err.send(Ok(Event::default().event("log").data(line))).await;
                    }
                }
            }
        });
        let _ = h1.await;
        let _ = h2.await;
        let status = child.wait().await;

        if !status.map(|s| s.success()).unwrap_or(false) || !proof_path.exists() {
            send("error", "Proof generation failed".to_string()).await;
            return;
        }
        let prove_elapsed = prove_start.elapsed();
        send(
            "log",
            format!("Derive proven in {:.2}s", prove_elapsed.as_secs_f64()),
        )
        .await;

        // ── Phase 2: read proof, proof_facts, and the L2->L1 message payload ──
        let proof_b64 = match tokio::fs::read_to_string(&proof_path).await {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                send("error", format!("Failed to read proof: {e}")).await;
                return;
            }
        };
        let proof_facts_str = match tokio::fs::read_to_string(proof_path.with_extension("proof_facts"))
            .await
        {
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
        // proof_facts[2] is the proven program hash (ProofFacts.virtual_os_program_hash).
        // Surface it so the operator can pin VEIL_DERIVE_PROGRAM_HASH in Veil.cairo.
        if let Some(program_hash) = proof_facts_hex.get(2) {
            send(
                "program_hash",
                serde_json::json!({ "virtual_os_program_hash": program_hash }).to_string(),
            )
            .await;
            send(
                "log",
                format!("Proven program hash (pin VEIL_DERIVE_PROGRAM_HASH to this): {program_hash}"),
            )
            .await;
        }
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

        let messages_path = proof_path.with_extension("raw_messages.json");
        let messages_str = match tokio::fs::read_to_string(&messages_path).await {
            Ok(s) => s,
            Err(_) => {
                send(
                    "error",
                    "No L2->L1 message emitted by the derive run (raw_messages.json missing). \
                     The derive function must call send_message_to_l1_syscall."
                        .to_string(),
                )
                .await;
                return;
            }
        };
        let message_payload = match extract_message_payload(&messages_str) {
            Ok(p) => p,
            Err(e) => {
                send("error", format!("Failed to read L2->L1 message: {e}")).await;
                return;
            }
        };
        send(
            "log",
            format!("Derived message payload: {} felts", message_payload.len()),
        )
        .await;

        // ── Phase 3: assemble settle calldata from the source table ──
        let mut settle_calldata: Vec<Felt> = Vec::with_capacity(spec.settle_sources.len());
        for (i, src) in spec.settle_sources.iter().enumerate() {
            // MsgRest copies many felts (the message tail, incl. a trailing
            // variable-length array); the others copy exactly one.
            if let Src::ExtraRest(start) = src {
                match settle_extra.get(*start..) {
                    Some(slice) => settle_calldata.extend_from_slice(slice),
                    None => {
                        send(
                            "error",
                            format!(
                                "settle source {i} (extra[{start}..]) is out of range (extra={})",
                                settle_extra.len(),
                            ),
                        )
                        .await;
                        return;
                    }
                }
                continue;
            }
            if let Src::MsgRest(start) = src {
                match message_payload.get(*start..) {
                    Some(slice) => settle_calldata.extend_from_slice(slice),
                    None => {
                        send(
                            "error",
                            format!(
                                "settle source {i} (msg[{start}..]) is out of range (msg={})",
                                message_payload.len(),
                            ),
                        )
                        .await;
                        return;
                    }
                }
                continue;
            }
            let value = match src {
                Src::Msg(idx) => message_payload.get(*idx).copied(),
                Src::Derive(idx) => derive_calldata.get(*idx).copied(),
                Src::Extra(idx) => settle_extra.get(*idx).copied(),
                Src::MsgRest(_) | Src::ExtraRest(_) => unreachable!(),
            };
            match value {
                Some(v) => settle_calldata.push(v),
                None => {
                    send(
                        "error",
                        format!(
                            "settle source {i} ({}) is out of range (msg={}, derive={}, extra={})",
                            describe_src(src),
                            message_payload.len(),
                            derive_calldata.len(),
                            settle_extra.len(),
                        ),
                    )
                    .await;
                    return;
                }
            }
        }

        // ── Phase 4: re-sign the settle call WITH proof_facts and submit ──
        send("phase", "submitting".to_string()).await;
        let settle_execute = build_execute_calldata(veil_address, settle_selector, &settle_calldata);

        let resource_bounds_submit = match state.rpc.resource_bounds().await {
            Ok(rb) => rb,
            Err(e) => {
                send("error", format!("Failed to fetch gas prices: {e}")).await;
                return;
            }
        };
        let params = SubmitParams {
            sender_address: sender_felt,
            private_key: private_key_felt,
            calldata: settle_execute,
            proof_base64: proof_b64,
            proof_facts,
            nonce: nonce_felt,
            chain_id,
            resource_bounds: resource_bounds_submit,
        };
        let (local_tx_hash, invoke_tx) = match sign_and_build_payload(&params) {
            Ok(r) => r,
            Err(e) => {
                send("error", format!("Settle signing failed: {e}")).await;
                return;
            }
        };
        let local_tx_hash_hex = format!("{local_tx_hash:#x}");

        let gateway_url = match state.config.gateway_url.as_deref() {
            Some(g) => g,
            None => {
                send(
                    "error",
                    "STARKNET_GATEWAY_URL is not set; SNIP-36 proofs must be submitted via the \
                     sequencer gateway, not a standard RPC node."
                        .to_string(),
                )
                .await;
                return;
            }
        };
        let submit_url = format!("{}/gateway/add_transaction", gateway_url.trim_end_matches('/'));
        send("log", format!("Submitting settle tx {local_tx_hash_hex} via gateway...")).await;

        let client = reqwest::Client::new();
        let submitted = match client
            .post(&submit_url)
            .header("Content-Type", "application/json")
            .json(&invoke_tx)
            .timeout(std::time::Duration::from_secs(120))
            .send()
            .await
        {
            Ok(resp) => {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
                if code == "TRANSACTION_RECEIVED" {
                    local_tx_hash_hex.clone()
                } else {
                    send("error", format!("Gateway rejected: {body}")).await;
                    return;
                }
            }
            Err(e) => {
                send("error", format!("Gateway request failed: {e}")).await;
                return;
            }
        };

        send(
            "complete",
            serde_json::json!({
                "operation": operation,
                "tx_hash": submitted,
                "local_tx_hash": local_tx_hash_hex,
                "reference_block": reference_block,
                "proof_duration_secs": prove_elapsed.as_secs_f64(),
                "settle_calldata_len": settle_calldata.len(),
            })
            .to_string(),
        )
        .await;
    });

    Ok(Sse::new(ReceiverStream::new(rx)))
}

fn describe_src(src: &Src) -> String {
    match src {
        Src::Msg(i) => format!("msg[{i}]"),
        Src::Derive(i) => format!("derive[{i}]"),
        Src::Extra(i) => format!("extra[{i}]"),
        Src::MsgRest(i) => format!("msg[{i}..]"),
        Src::ExtraRest(i) => format!("extra[{i}..]"),
    }
}

/// Extract the first L2->L1 message payload from the prover's raw_messages.json,
/// which has shape `{"l2_to_l1_messages": [{"from_address","to_address","payload":[..]}]}`.
fn extract_message_payload(json_str: &str) -> Result<Vec<Felt>, String> {
    let root: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("invalid JSON: {e}"))?;
    let messages = root
        .get("l2_to_l1_messages")
        .and_then(|v| v.as_array())
        .ok_or("missing l2_to_l1_messages array")?;
    let first = messages.first().ok_or("no L2->L1 messages emitted")?;
    let payload = first
        .get("payload")
        .and_then(|v| v.as_array())
        .ok_or("message has no payload array")?;
    payload
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| "payload entry not a string".to_string())
                .and_then(|s| felt_from_hex(s))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erc3643_batch_settle_is_the_whole_proven_message() {
        let spec = op_spec("erc3643", "execute_batch").expect("execute_batch is an erc3643 op");
        assert!(matches!(spec.settle_sources.as_slice(), [Src::MsgRest(0)]));
        assert!(op_spec("erc721", "execute_batch").is_none());
    }

    #[test]
    fn erc3643_venue_fill_settle_is_the_whole_proven_message() {
        let spec = op_spec("erc3643", "venue_fill").expect("venue_fill is an erc3643 op");
        assert!(matches!(spec.settle_sources.as_slice(), [Src::MsgRest(0)]));
        // starknet_keccak("venue_fill_derive") / ("venue_fill_settle").
        assert_eq!(
            spec.derive_selector,
            "0x786b1ae69ce9d64b9bfa976a1ea2a0ecb7cc231b73f40c8d16f48ef6844f78"
        );
        assert_eq!(
            spec.settle_selector,
            "0x3b50e5e369934aac23d985c1054dab9dfa5bb379644cdd6229641070e29bf4a"
        );
        assert!(op_spec("erc721", "venue_fill").is_none());
    }
}
