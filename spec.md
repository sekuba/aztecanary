# aztecanary.js specification

This document captures the assumptions, invariants, and high-level logic implemented in `aztecanary.js`.

## Core assumptions
- The rollup contract address is fixed at `0x603bb2c05D474794ea97805e8De69bCcFb3bCA12`.
- Chain-provided parameters are authoritative: `genesisTime`, `slotDuration`, `epochDuration`, `lag`, epoch committees, and sample seeds.
- `L2BlockProposed` is emitted exactly once per successful `propose` call.
- Proposals for a slot are authored only by the deterministic proposer for that slot; proposer mismatches indicate a decode/lookup issue on our side.
- `_signers` in the propose call reflect attesters (only attesters who successfully signed); `signatureIndices` bitset is a secondary source.
- A slot with no observed `propose` tx implies no attestations are available for inspection; we do not mark attestation misses for such slots, only proposal miss.
- Watchlist is provided via `TARGETS` env var; monitoring requires at least one target.
- L1 Ethereum block time is exactly 12s post-merge; slot duration is an integer multiple of that (e.g., 72s = 6 L1 blocks). This is used to bound history scans to the current epoch.
- RPC access is trusted and stable; no network retries are built in.

## Key constants
- `RPC_URL`: JSON-RPC endpoint (env or default `http://127.0.0.1:8545`).
- `HEALTH_CHECK_INTERVAL_BLOCKS`: how often to poll validator status (default 50 L1 blocks).
- `lag`: read from chain; controls how far ahead we predict proposer duties.

## Important data structures
- `TARGET_SEQUENCERS`: Set of lowercased addresses from `TARGETS`.
- `epochCache`: `epoch -> { committee[], seed }`, capped at 20 entries.
- `processedEpochs`: epochs already logged for committee/duty info (still reused for heartbeat).
- `proposedSlots`: Set of slot numbers (string) where a `propose` tx was observed.
- `checkedL2Blocks`: L2 block numbers already analyzed to avoid duplicate processing.
- `lastCheckedSlot`: last slot boundary evaluated for empty-slot proposal misses.

## Deterministic computations
- Slot index from time: `(block.timestamp - genesisTime) / slotDuration`.
- Epoch index: `slot / epochDuration`.
- Proposer index: `keccak256(epoch, slot, seed) mod committeeSize`.
- Duty prediction: iterate slots for current and `lag` epochs using cached committee+seed.

## Proposer resolution logic
Call `rollup.getCurrentProposer` at the tx block tag; if it fails or returns empty, we abort processing for that tx and log an error.
Proposer mismatches vs the deterministic expected proposer are treated as decode issues; attestation checks are skipped in that case.

## Attestation resolution logic
- Prefer `_signers` for membership; fallback to `signatureIndices` bitset for a committee index when `_signers` does not include the validator.
- Attestation misses are only evaluated when:
  - A `propose` tx exists for the slot, and
  - Decoded proposer matches the expected deterministic proposer.
- For each tracked validator in the committee, if neither `_signers` nor the bitset shows participation, we log `ATTEST_MISS`.

## Proposal miss logic
- On every L1 block, after processing observed `propose` events, `markMissedSlotsUntil` walks all fully elapsed slots between `lastCheckedSlot` and `currentSlot - 1`.
- If no proposal was observed for a slot (`proposedSlots` lacks it) and the expected proposer is tracked, log `PROPOSAL_MISS`.
- The current slot is only evaluated on the next block, avoiding premature misses.

## History audit (startup)
- On init, audit the current epoch only:
  - Compute the epoch start slot/time and, using fixed 12s L1 blocks plus slot duration, derive a tight `fromBlock` near the epoch start (with a small cushion).
  - For each `L2BlockProposed`, call `checkBlockPerf` (with summaries, no realtime logs).
  - For slots in the epoch with no observed proposal, record a proposal miss for tracked expected proposers.
  - Emit `AUDIT_SUMMARY` for proposal misses and attestation misses.

## Realtime flow
1) `handleBlock` runs per L1 block.
2) Compute current slot/epoch from timestamp; call `predictDuties` for current+lag epochs to populate heartbeat and caches.
3) Heartbeat (every 10 L1 blocks) prints L1 block, current epoch/slot, current attesters, and all upcoming proposer duties within the lag window.
4) If there are tracked validators in the current committee, pull `L2BlockProposed` logs for the block and run `checkBlockPerf` for each.
5) After log processing, call `markMissedSlotsUntil` to emit proposal misses for empty slots that have fully elapsed.

## Duty prediction and caching
- `predictDuties` fetches committee+seed per epoch once; subsequent calls reuse cached data when `processedEpochs` marks an epoch as processed.
- Proposer duties are logged once per epoch; heartbeat uses cached proposals to keep showing upcoming duties across the lag window.

## Validator status checks
- `getAttesterView` is polled every `HEALTH_CHECK_INTERVAL_BLOCKS`; non-VALIDATING statuses raise `ALERT`.

## Logging semantics
- `DUTY:PROPOSAL_MISS`: expected tracked proposer did not propose for a slot (no proposal observed).
- `DUTY:PROPOSAL_OK`: tracked proposer proposed their slot.
- `DUTY:ATTEST_MISS`: tracked validator absent from both `_signers` and bitset for a slot with a valid proposal.
- `ERROR` (proposer mismatch): decoded proposer disagrees with deterministic proposer; treated as a decode/lookup bug; attestation checks skipped.
- `AUDIT_SUMMARY`: startup summaries for misses in the current epoch.
- Heartbeat: periodic snapshot of current L1 block, epoch/slot, current attesters, and all upcoming proposer duties within lag.
