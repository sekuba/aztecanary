# Aztecanary (Python) Specification

This document outlines the logic, assumptions, and architecture of `aztecanary.py`, a single-file monitor for Aztec L2 sequencers.

## 1. Scope & Purpose
The script monitors specific Ethereum addresses (Sequencers) to ensure they are fulfilling their duties on the Aztec L2 rollup. It detects:
1.  **Missed Proposals**: A tracked sequencer failed to propose a block in their assigned slot.
2.  **Missed Attestations**: A tracked sequencer failed to attest to a valid block in their committee.
3.  **Validator Status**: A tracked sequencer drops out of the `VALIDATING` state (e.g., becomes `ZOMBIE` or `EXITING`).

## 2. Configuration
*   **Environment Variables**:
    *   `RPC_URL`: Ethereum JSON-RPC endpoint.
    *   `TARGETS`: Comma-separated list of validator addresses to monitor.
*   **Constants**:
    *   `ROLLUP_ADDRESS`: `0x603bb2c05D474794ea97805e8De69bCcFb3bCA12`.
    *   `L1_BLOCK_TIME`: Fixed at 12 seconds (used for historical scan window math).

## 3. Core Logic & Math

### Time Resolution
Aztec time is derived deterministically from L1 timestamps:
*   `CurrentSlot = (L1_Timestamp - GenesisTime) / SlotDuration`
*   `CurrentEpoch = CurrentSlot / EpochDuration`

### Proposer Selection
The expected proposer for a slot is calculated using the Solidity-equivalent logic:
*   **Input**: `Epoch`, `Slot`, `Seed` (from `getSampleSeedAt`), `CommitteeSize`.
*   **Formula**: `uint256(keccak256(abi.encode(epoch, slot, seed))) % committee_size`.
*   **Result**: Index in the sorted committee array.

### Transaction Decoding
The script robustly identifies L2 blocks by decoding L1 transactions:
1.  **Direct Calls**: Checks if `tx.input` matches `rollup.propose(...)`.
2.  **Multicall3**: Parses `aggregate3` calls to find nested `rollup.propose` payloads.

### Attestation Verification
For every tracked validator in the committee, the script checks presence in the `_signers` array of the proposal.
*   **Alert**: If a tracked validator is absent from `_signers`, it is flagged as a missed attestation.

## 4. Operational Modes

### A. Real-Time Monitor (Default)
Runs an infinite loop processing the L1 chain tip.
1.  **Heartbeat**: Logs L1 block, Aztec Epoch/Slot once per slot (aligned to slot boundaries) and reports proposal ETA plus attestation status (`Attest: current epoch` or `Attest in: <duration>` if a tracked validator is in a future committee).
2.  **Health Check**: Validator status is checked every slot; alerts fire on startup for non-`VALIDATING` or on any subsequent status change.
3.  **Duty Prediction**: Once per epoch (or when the nearest duty changes), logs tracked proposal duties for the current epoch plus the lookahead lag (e.g., 3 epochs total if `lag=2`), annotating the nearest duty with a human-readable time to go.
4.  **Event Processing**: Listens for `L2BlockProposed`. On event:
    *   Decodes the transaction via Multicall3 `aggregate3` -> `propose` to extract `_signers` and slot.
    *   Assumes the proposal succeeded if the transaction landed; logs success for tracked proposers based on deterministic duty mapping.
    *   Checks for missing attestations from tracked validators (signer-list only).
5.  **Silence Detection**: If the L1 chain advances but no L2 block is seen for a slot assigned to a tracked sequencer, triggers a **PROPOSAL MISS** alert.

### B. Historical Scan (`-scan [value]`)
Audits past performance over a defined range (`24h`, `10d`, `50` blocks, or `5e` epochs).
1.  Calculates `from_block` based on the lookback value (epochs converted via epoch/slot durations, hours/days via 12s L1 time).
2.  Fetches all `L2BlockProposed` logs in range and decodes each for attestation checks.
3.  Reconstructs the slot range covered by observed logs and flags missed proposals for tracked proposers if a slot lacked a corresponding proposal.
4.  Outputs totals for observed blocks, attestation misses, and proposal misses.

## 5. Logging Levels
*   **[INFO]**: Normal operation, heartbeats, upcoming duties.
*   **[ALERT]**: Actionable items (Missed Proposal, Missed Attestation, Invalid Validator Status).
*   **[ERROR]**: RPC connection failures, decoding errors, or script crashes.
