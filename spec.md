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
    *   `L1_BLOCK_TIME`: Fixed at 12 seconds.
    *   `HEALTH_CHECK_INTERVAL`: 50 L1 blocks.

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
Attestations are stored in a bitmap within the `propose` arguments.
*   **Check**: For every tracked validator in the committee, the script checks if their specific bit is set in `signatureIndices`.
*   **Alert**: If the bit is 0 and the validator address is not in the explicit `_signers` array, it is flagged as a missed attestation.

## 4. Operational Modes

### A. Real-Time Monitor (Default)
Runs an infinite loop processing the L1 chain tip.
1.  **Heartbeat**: Logs L1 block, Aztec Epoch/Slot every 10 blocks.
2.  **Duty Prediction**: Calculates upcoming proposer slots for tracked targets based on the `lag` parameter and caches them.
3.  **Event Processing**: Listens for `L2BlockProposed`. On event:
    *   Decodes the transaction.
    *   Verifies if the proposer was the expected one.
    *   Checks for missing attestations from tracked validators.
4.  **Silence Detection**: If the L1 chain advances but no L2 block is seen for a slot assigned to a tracked sequencer, triggers a **PROPOSAL MISS** alert.

### B. Historical Scan (`-scan [value]`)
Audits past performance over a defined range (e.g., `24h` or `100` blocks).
1.  Calculates `from_block` based on the lookback value and 12s block time.
2.  Fetches all `L2BlockProposed` logs in range.
3.  Performs the **Attestation Verification** logic on every log found.
4.  Outputs a summary of total blocks observed and total attestations missed.

## 5. Logging Levels
*   **[INFO]**: Normal operation, heartbeats, upcoming duties.
*   **[ALERT]**: Actionable items (Missed Proposal, Missed Attestation, Invalid Validator Status).
*   **[ERROR]**: RPC connection failures, decoding errors, or script crashes.