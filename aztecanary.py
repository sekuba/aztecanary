#!/usr/bin/env python3
"""
aztecanary - Aztec Sequencer Monitor (Python 3.13)
Single-file, portable script to monitor Aztec L2 sequencers.

Usage:
  export RPC_URL="http://127.0.0.1:8545"
  export TARGETS="0x123...,0x456..."
  python aztecanary.py              # Real-time monitoring
  python aztecanary.py -scan 100    # Scan last 100 L1 blocks
  python aztecanary.py -scan 24h    # Scan last 24 hours
  python aztecanary.py -scan e984   # Scan only epoch 984
"""

import os
import sys
import time
import logging
import argparse
from typing import Dict, List, Optional, Set, Tuple, Any

from web3 import Web3
from eth_abi import decode
from eth_utils import to_checksum_address

# --- Configuration & Constants ---

RPC_URL = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
TARGETS_ENV = os.environ.get("TARGETS", "")
ROLLUP_ADDRESS = "0x603bb2c05D474794ea97805e8De69bCcFb3bCA12"
AGGREGATE3_SELECTOR = "0x82ad56cb"
L1_BLOCK_TIME_SEC = 12
PROPOSE_SELECTOR = "0x48aeda19"
# Hardcoded immutables (from deployed bytecode)
GENESIS_TIME = 1762995155
SLOT_DURATION = 72
EPOCH_DURATION = 32

# Minimal ABIs for interactions
ROLLUP_ABI = [
    # Events
    {"anonymous": False, "inputs": [{"indexed": True, "internalType": "uint256", "name": "blockNumber", "type": "uint256"}, {"indexed": True, "internalType": "bytes32", "name": "archive", "type": "bytes32"}, {"indexed": False, "internalType": "bytes32[]", "name": "versionedBlobHashes", "type": "bytes32[]"}], "name": "L2BlockProposed", "type": "event"},
    # View Functions
    {"inputs": [], "name": "getLagInEpochs", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "uint256", "name": "_epoch", "type": "uint256"}], "name": "getEpochCommittee", "outputs": [{"internalType": "address[]", "name": "", "type": "address[]"}], "stateMutability": "nonpayable", "type": "function"}, # Non-view in source; used read-only here
    {"inputs": [{"internalType": "uint256", "name": "_ts", "type": "uint256"}], "name": "getSampleSeedAt", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "_attester", "type": "address"}], "name": "getAttesterView", "outputs": [{"components": [{"internalType": "uint8", "name": "status", "type": "uint8"}, {"internalType": "uint256", "name": "effectiveBalance", "type": "uint256"}], "internalType": "struct AttesterView", "name": "", "type": "tuple"}], "stateMutability": "view", "type": "function"},
    # Propose Function (for decoding tx input)
    {"inputs": [{"components": [{"internalType": "bytes32", "name": "archive", "type": "bytes32"}, {"components": [{"components": [{"internalType": "bytes32", "name": "root", "type": "bytes32"}, {"internalType": "uint32", "name": "nextAvailableLeafIndex", "type": "uint32"}], "internalType": "struct PartialTreeRoot", "name": "l1ToL2MessageTree", "type": "tuple"}, {"components": [{"components": [{"internalType": "bytes32", "name": "root", "type": "bytes32"}, {"internalType": "uint32", "name": "nextAvailableLeafIndex", "type": "uint32"}], "internalType": "struct PartialTreeRoot", "name": "noteHashTree", "type": "tuple"}, {"components": [{"internalType": "bytes32", "name": "root", "type": "bytes32"}, {"internalType": "uint32", "name": "nextAvailableLeafIndex", "type": "uint32"}], "internalType": "struct PartialTreeRoot", "name": "nullifierTree", "type": "tuple"}, {"components": [{"internalType": "bytes32", "name": "root", "type": "bytes32"}, {"internalType": "uint32", "name": "nextAvailableLeafIndex", "type": "uint32"}], "internalType": "struct PartialTreeRoot", "name": "publicDataTree", "type": "tuple"}], "internalType": "struct PartialStateReference", "name": "partialStateReference", "type": "tuple"}], "internalType": "struct StateReference", "name": "stateReference", "type": "tuple"}, {"components": [{"internalType": "int256", "name": "feeAssetPriceModifier", "type": "int256"}], "internalType": "struct OracleInput", "name": "oracleInput", "type": "tuple"}, {"components": [{"internalType": "bytes32", "name": "lastArchiveRoot", "type": "bytes32"}, {"components": [{"internalType": "bytes32", "name": "blobsHash", "type": "bytes32"}, {"internalType": "bytes32", "name": "inHash", "type": "bytes32"}, {"internalType": "bytes32", "name": "outHash", "type": "bytes32"}], "internalType": "struct ContentCommitment", "name": "contentCommitment", "type": "tuple"}, {"internalType": "uint256", "name": "slotNumber", "type": "uint256"}, {"internalType": "uint256", "name": "timestamp", "type": "uint256"}, {"internalType": "address", "name": "coinbase", "type": "address"}, {"internalType": "bytes32", "name": "feeRecipient", "type": "bytes32"}, {"components": [{"internalType": "uint128", "name": "feePerDaGas", "type": "uint128"}, {"internalType": "uint128", "name": "feePerL2Gas", "type": "uint128"}], "internalType": "struct GasFees", "name": "gasFees", "type": "tuple"}, {"internalType": "uint256", "name": "totalManaUsed", "type": "uint256"}], "internalType": "struct Header", "name": "header", "type": "tuple"}], "internalType": "struct ProposeArgs", "name": "_args", "type": "tuple"}, {"components": [{"internalType": "bytes", "name": "signatureIndices", "type": "bytes"}, {"internalType": "bytes", "name": "signaturesOrAddresses", "type": "bytes"}], "internalType": "struct CommitteeAttestations", "name": "_attestations", "type": "tuple"}, {"internalType": "address[]", "name": "_signers", "type": "address[]"}, {"components": [{"internalType": "uint8", "name": "v", "type": "uint8"}, {"internalType": "bytes32", "name": "r", "type": "bytes32"}, {"internalType": "bytes32", "name": "s", "type": "bytes32"}], "internalType": "struct ECDSAData", "name": "_attestationsAndSignersSignature", "type": "tuple"}, {"internalType": "bytes", "name": "_blobInput", "type": "bytes"}], "name": "propose", "type": "function"}
]

# Logging Setup
class CustomFormatter(logging.Formatter):
    FORMATS = {
        logging.INFO: "\033[94m[INFO]\033[0m %(message)s",
        logging.WARNING: "\033[93m[ALERT]\033[0m %(message)s",
        logging.ERROR: "\033[91m[ERROR]\033[0m %(message)s",
    }
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, "%(message)s")
        formatter = logging.Formatter(f"%(asctime)s {log_fmt}", datefmt="%Y-%m-%d %H:%M:%S")
        return formatter.format(record)

handler = logging.StreamHandler()
handler.setFormatter(CustomFormatter())
logger = logging.getLogger("Aztecanary")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# --- Helper Functions ---

def parse_targets(raw_targets: str) -> Set[str]:
    return {to_checksum_address(t.strip()) for t in raw_targets.split(",") if t.strip()}

def format_duration(seconds: int) -> str:
    m, s = divmod(max(0, int(seconds)), 60)
    return f"{m}m {s}s" if m > 0 else f"{s}s"

def compute_proposer_index(epoch: int, slot: int, seed: int, committee_size: int) -> int:
    if committee_size == 0:
        return 0
    # Solidity: uint256(keccak256(abi.encode(_epoch, _slot, _seed))) % _size
    packed = Web3.solidity_keccak(['uint256', 'uint256', 'uint256'], [epoch, slot, seed])
    return int.from_bytes(packed, byteorder='big') % committee_size

# --- Main Logic Class ---

class Aztecanary:
    def __init__(self, targets: Set[str]):
        if not targets:
            logger.error("TARGETS is required. Set the TARGETS env var (comma-separated addresses).")
            sys.exit(1)
        self.targets = targets
        self.w3 = Web3(Web3.HTTPProvider(RPC_URL))
        self.rollup = self.w3.eth.contract(address=ROLLUP_ADDRESS, abi=ROLLUP_ABI)
        
        self.config: Dict[str, int] = {}
        self.epoch_cache: Dict[int, Dict[str, Any]] = {}  # {epoch: {committee: [], seed: int}}
        self.processed_slots: Set[int] = set()
        self.last_checked_slot: Optional[int] = None
        self.status_cache: Dict[str, str] = {}
        self.last_predicted_epoch: Optional[int] = None
        self.next_duty_slot: Optional[int] = None
        self.next_duty_slot_ts: Optional[float] = None
        self.attest_current_epoch: bool = False
        self.next_attest_epoch: Optional[int] = None
        self.next_attest_ts: Optional[float] = None

    def init_chain_params(self):
        """Initializes chain parameters (immutables are hardcoded)."""
        logger.info("Initializing chain parameters...")
        if not self.w3.is_connected():
            logger.error("Could not connect to RPC")
            sys.exit(1)

        try:
            self.config = {
                "genesis_time": GENESIS_TIME,
                "slot_duration": SLOT_DURATION,
                "epoch_duration": EPOCH_DURATION,
                "lag": self.rollup.functions.getLagInEpochs().call(),
            }

            logger.info(f"Chain Params: EpochDur={self.config['epoch_duration']} slots, "
                        f"SlotDur={self.config['slot_duration']}s, Lag={self.config['lag']} epochs")
            logger.info(f"Tracking {len(self.targets)} sequencers: {', '.join(self.targets)}...")

        except Exception as e:
            logger.error(f"Failed to initialize chain params: {e}")
            sys.exit(1)

    def get_epoch_data(self, epoch: int) -> Dict:
        """Fetches or retrieves cached committee and seed for an epoch."""
        if epoch in self.epoch_cache:
            return self.epoch_cache[epoch]

        try:
            ts = self.config['genesis_time'] + (epoch * self.config['epoch_duration'] * self.config['slot_duration'])
            committee = self.rollup.functions.getEpochCommittee(epoch).call()
            seed = self.rollup.functions.getSampleSeedAt(ts).call()
            
            data = {
                "committee": [to_checksum_address(addr) for addr in committee],
                "seed": seed
            }
            
            # Cache management (keep last 20 epochs)
            self.epoch_cache[epoch] = data
            if len(self.epoch_cache) > 20:
                oldest = min(self.epoch_cache.keys())
                del self.epoch_cache[oldest]
                
            return data
        except Exception as e:
            logger.error(f"Failed to fetch data for Epoch {epoch}: {e}")
            sys.exit(1)

    def check_validator_status(self):
        """Polls the status of tracked validators."""
        status_map = {0: "NONE", 1: "VALIDATING", 2: "ZOMBIE", 3: "EXITING"}
        
        for target in self.targets:
            try:
                view = self.rollup.functions.getAttesterView(target).call()
                status_code = view[0]
                # effective_balance = view[1]
                
                status_str = status_map.get(status_code, "UNKNOWN")
                previous_status = self.status_cache.get(target)
                self.status_cache[target] = status_str

                # Startup alert for non-validating statuses
                if previous_status is None and status_str != "VALIDATING":
                    logger.warning(f"Sequencer {target} status is {status_str} (Balance: {self.w3.from_wei(view[1], 'ether')} ETH)")
                    continue

                # Alert only on status changes after startup
                if previous_status is not None and status_str != previous_status:
                    logger.warning(f"Sequencer {target} status changed: {previous_status} -> {status_str} (Balance: {self.w3.from_wei(view[1], 'ether')} ETH)")
            except Exception as e:
                logger.error(f"Failed to check status for {target}: {e}")

    def _decode_propose_call(self, call_data: bytes) -> Optional[Dict]:
        """Decodes a propose call payload to extract signers and slot."""
        if len(call_data) < 4 or call_data[:4].hex() != PROPOSE_SELECTOR[2:]:
            return None

        try:
            data_hex = "0x" + call_data.hex()
            fn, params = self.rollup.decode_function_input(data_hex)
            if getattr(fn, "fn_name", "") != "propose":
                return None

            signers = [to_checksum_address(s) for s in params["_signers"]]
            slot_num = params["_args"]["header"]["slotNumber"]
            return {"_signers": signers, "slot": slot_num}
        except Exception as e:
            prefix = call_data[:16].hex()
            logger.error(
                f"decode_propose_call failure: {e} | calldatalen={len(call_data)} prefix=0x{prefix}"
            , exc_info=True)
            return None

    def decode_propose_tx(self, tx) -> Optional[Dict]:
        """
        Decodes a transaction to find the `propose` call arguments.
        Handles Multicall3 aggregate3 (0x82ad56cb) wrapping propose.
        """
        input_hex = tx.input if isinstance(tx.input, str) else tx.input.hex()
        if not input_hex.startswith("0x"):
            input_hex = "0x" + input_hex

        selector = input_hex[:10]

        if selector == AGGREGATE3_SELECTOR:
            try:
                raw_data = bytes.fromhex(input_hex[10:])
                decoded_calls = decode(['(address,bool,bytes)[]'], raw_data)[0]
            except Exception as e:
                logger.error(f"decode_propose_tx aggregate3 decode failure: {e}", exc_info=True)
                return None

            for (target, _, call_data) in decoded_calls:
                if to_checksum_address(target) == ROLLUP_ADDRESS:
                    if len(call_data) < 4:
                        logger.error(f"decode_propose_tx: call_data too short ({len(call_data)}) for rollup target in tx {tx.hash.hex()}")
                        continue
                    propose = self._decode_propose_call(call_data)
                    if propose:
                        return propose
        return None

    def analyze_block_perf(self, l2_block_num: int, tx_hash: str, context: str = "REALTIME") -> Tuple[Optional[str], List[str], Optional[List[str]], List[str]]:
        """
        Analyzes a specific L2 block proposal for proposer correctness and attestations.
        Returns (ProposerAddress, List[MissedAttesters], Committee, Signers).
        """
        try:
            tx = self.w3.eth.get_transaction(tx_hash)
            args = self.decode_propose_tx(tx)
            if not args:
                logger.error(f"[{context}] Could not decode propose tx for L2 block {l2_block_num}; duty checks incomplete")
                return None, [], None, []

            # Extract from tx args and on-chain block view
            signers = args["_signers"]
            slot = args["slot"]

            self.processed_slots.add(slot)
            
            epoch = slot // self.config['epoch_duration']
            epoch_data = self.get_epoch_data(epoch)
            
            committee = epoch_data['committee']
            committee_size = len(committee)

            expected_proposer = None
            if committee_size > 0:
                expected_idx = compute_proposer_index(epoch, slot, epoch_data['seed'], committee_size)
                expected_proposer = committee[expected_idx]
                if expected_proposer in self.targets:
                    logger.info(f"[{context}] DUTY: PROPOSAL_OK - Block {l2_block_num} (Slot {slot}) proposed by tracked {expected_proposer[:8]}")
        
            missed_attesters: List[str] = []

            # Verify attestations using signer list only
            for _, validator in enumerate(committee):
                if validator in self.targets:
                    if validator not in signers:
                        logger.warning(f"[{context}] DUTY: ATTEST_MISS - {validator[:8]} attestation not included for Block {l2_block_num} (committee member). txhash={tx_hash.hex()}")
                        missed_attesters.append(validator)
            
            return expected_proposer, missed_attesters, committee, signers

        except Exception as e:
            logger.error(f"[{context}] Error analyzing block {l2_block_num}: {e}")
            return None, [], None, []

    def check_missed_slots(self, current_slot: int):
        """Checks if any slots between last check and now were missed (empty)."""
        if self.last_checked_slot is None:
            self.last_checked_slot = current_slot
            return

        # Only check fully elapsed slots
        start = self.last_checked_slot
        end = current_slot - 1 
        
        if start > end:
            return

        for s in range(start, end + 1):
            if s in self.processed_slots:
                continue
            
            epoch = s // self.config['epoch_duration']
            epoch_data = self.get_epoch_data(epoch)
            idx = compute_proposer_index(epoch, s, epoch_data['seed'], len(epoch_data['committee']))
            expected_proposer = epoch_data['committee'][idx]
            
            if expected_proposer in self.targets:
                logger.warning(f"[REALTIME] DUTY: PROPOSAL_MISS - Slot {s} missed by tracked {expected_proposer}")
        
        self.last_checked_slot = current_slot

    def predict_upcoming_duties(self, start_epoch: int, current_slot: int, anchor_ts: int):
        """
        Logs proposal duties for tracked sequencers for current epoch plus lag
        and tracks the nearest duty for heartbeat display.
        """
        lookahead_epochs = self.config['lag']
        summaries = []
        nearest: Optional[Dict[str, Any]] = None
        now_ts = anchor_ts
        attest_current = False
        next_attest_epoch: Optional[int] = None
        next_attest_ts: Optional[float] = None

        for e in range(start_epoch, start_epoch + lookahead_epochs + 1):
            data = self.get_epoch_data(e)
            committee = data["committee"]
            start_slot = e * self.config["epoch_duration"]
            end_slot = start_slot + self.config["epoch_duration"]
            targets_in_committee = any(v in self.targets for v in committee)
            if targets_in_committee:
                if e == start_epoch:
                    attest_current = True
                elif next_attest_epoch is None:
                    next_attest_epoch = e
                    next_attest_ts = self.config["genesis_time"] + (start_slot * self.config["slot_duration"])

            tracked_duties = []
            for s in range(max(start_slot, current_slot), end_slot):
                idx = compute_proposer_index(e, s, data["seed"], len(committee))
                proposer = committee[idx]
                if proposer in self.targets:
                    slot_ts = self.config["genesis_time"] + (s * self.config["slot_duration"])
                    delta = max(0, slot_ts - now_ts)
                    duty = {"slot": s, "proposer": proposer, "delta": delta, "slot_ts": slot_ts}
                    tracked_duties.append(duty)
                    if nearest is None or duty["delta"] < nearest["delta"]:
                        nearest = duty

            if tracked_duties:
                formatted = []
                for duty in tracked_duties:
                    suffix = ""
                    if nearest and duty["slot"] == nearest["slot"]:
                        suffix = f" (in {format_duration(int(nearest['delta']))})"
                    formatted.append(f"Slot {duty['slot']} ({duty['proposer'][:6]}){suffix}")
                summaries.append(f"Epoch {e}: {', '.join(formatted)}")

        if nearest:
            self.next_duty_slot = nearest["slot"]
            self.next_duty_slot_ts = nearest["slot_ts"]
        else:
            self.next_duty_slot = None
            self.next_duty_slot_ts = None

        self.attest_current_epoch = attest_current
        self.next_attest_epoch = next_attest_epoch
        self.next_attest_ts = next_attest_ts

        if summaries:
            logger.info(f"[DUTY] Upcoming Proposals: {' | '.join(summaries)}")

    def run_scan(self, lookback_str: str):
        """Historical scan mode."""
        self.init_chain_params()
        target_epoch: Optional[int] = None
        start_slot: Optional[int] = None
        end_slot: Optional[int] = None
        
        # Parse lookback (supports hours: h, epochs lookback: e, specific epoch: e<number>, or raw blocks)
        blocks_to_scan = 0
        look = lookback_str.strip().lower()

        latest_block = self.w3.eth.get_block('latest')
        latest_num = latest_block['number']
        latest_ts = latest_block['timestamp']

        if look.startswith("e") and look[1:].isdigit():
            target_epoch = int(look[1:])
            epoch_seconds = self.config["epoch_duration"] * self.config["slot_duration"]
            start_slot = target_epoch * self.config["epoch_duration"]
            end_slot = start_slot + self.config["epoch_duration"]
            start_ts = self.config["genesis_time"] + (start_slot * self.config["slot_duration"])
            end_ts = start_ts + epoch_seconds

            if start_ts > latest_ts:
                logger.warning(f"Requested epoch {target_epoch} is in the future; nothing to scan.")
                return

            # Binary search for the first block with timestamp > start_ts, then step back one.
            low, high = 0, latest_num
            while low < high:
                mid = (low + high) // 2
                if self.w3.eth.get_block(mid)['timestamp'] <= start_ts:
                    low = mid + 1
                else:
                    high = mid
            start_block = max(0, low - 1)

            # Binary search for the first block with timestamp >= end_ts; end_block is previous.
            low, high = 0, latest_num
            while low < high:
                mid = (low + high) // 2
                if self.w3.eth.get_block(mid)['timestamp'] < end_ts:
                    low = mid + 1
                else:
                    high = mid
            end_block = max(0, low - 1)

            from_block = start_block
            to_block = min(latest_num, end_block)

            logger.info(
                f"Scanning Epoch {target_epoch} (Slots {start_slot}-{end_slot - 1}) "
                f"from L1 Block {from_block} to {to_block} "
                f"(start_ts={start_ts}, end_ts={end_ts})"
            )
        else:
            if look.endswith("h"):
                hours = int(look[:-1])
                blocks_to_scan = (hours * 3600) // L1_BLOCK_TIME_SEC
            elif look.endswith("e"):
                epochs = int(look[:-1])
                seconds = epochs * self.config["epoch_duration"] * self.config["slot_duration"]
                blocks_to_scan = seconds // L1_BLOCK_TIME_SEC
            else:
                blocks_to_scan = int(lookback_str)

            from_block = max(0, latest_num - blocks_to_scan)
            to_block = latest_num
            logger.info(f"Starting Historical Scan from L1 Block {from_block} to {to_block} (~{blocks_to_scan} blocks)")
        
        logs = self.rollup.events.L2BlockProposed.get_logs(from_block=from_block, to_block=to_block)
        logger.info(f"Found {len(logs)} L2 Blocks proposed in range.")
        
        validator_stats: Dict[str, Dict[str, int]] = {
            v: {"proposal_ok": 0, "proposal_miss": 0, "attest_ok": 0, "attest_miss": 0}
            for v in self.targets
        }
        observed_slots: Set[int] = set()
        missed_props = 0
        missed_attests = 0
        processed_logs = 0
        min_slot = start_slot
        max_slot = end_slot - 1 if end_slot is not None else None
        
        for log in logs:
            l2_block = log['args']['blockNumber']
            slot = None
            try:
                tx = self.w3.eth.get_transaction(log['transactionHash'])
                decoded = self.decode_propose_tx(tx)
                if decoded and decoded.get("slot") is not None:
                    slot = decoded["slot"]
            except Exception as e:
                logger.error(f"[HISTORY] Unable to resolve slot for block {l2_block}: {e}")

            if slot is None:
                logger.error(f"[HISTORY] Skipping block {l2_block}; slot unknown")
                continue

            block_epoch = slot // self.config['epoch_duration']
            if target_epoch is not None and block_epoch != target_epoch:
                continue

            observed_slots.add(slot)
            processed_logs += 1
            if target_epoch is None:
                min_slot = slot if min_slot is None else min(min_slot, slot)
                max_slot = slot if max_slot is None else max(max_slot, slot)

            expected, misses, committee, signers = self.analyze_block_perf(l2_block, log['transactionHash'], context="HISTORY")
            if misses:
                missed_attests += len(misses)
            # Proposal stats
            if expected and expected in self.targets:
                validator_stats[expected]["proposal_ok"] += 1
            # Attestation stats
            if committee is not None:
                for val in committee:
                    if val in self.targets:
                        if signers and val in signers:
                            validator_stats[val]["attest_ok"] += 1
                        else:
                            validator_stats[val]["attest_miss"] += 1
        
        # Missed proposals: iterate slot range covered by observed logs
        if min_slot is not None and max_slot is not None:
            for s in range(min_slot, max_slot + 1):
                if s in observed_slots:
                    continue
                
                epoch = s // self.config['epoch_duration']
                epoch_data = self.get_epoch_data(epoch)

                proposer_idx = compute_proposer_index(epoch, s, epoch_data['seed'], len(epoch_data['committee']))
                expected_proposer = epoch_data['committee'][proposer_idx]
                if expected_proposer in self.targets:
                    missed_props += 1
                    validator_stats[expected_proposer]["proposal_miss"] += 1
                    logger.warning(f"[HISTORY] DUTY:PROPOSAL_MISS - Slot {s} missed by tracked {expected_proposer}")
        
        logger.info("-" * 40)
        logger.info(f"Scan Complete. Observed L2 Blocks: {processed_logs}")
        logger.info(f"Attestation Misses (Tracked): {missed_attests}")
        logger.info(f"Proposal Misses (Tracked): {missed_props}")
        printed = False
        for val, stats in validator_stats.items():
            total = sum(stats.values())
            if total == 0:
                continue
            printed = True
            logger.info(f"[STATS] {val[:8]} proposals ok/miss: {stats['proposal_ok']}/{stats['proposal_miss']} | attests ok/miss: {stats['attest_ok']}/{stats['attest_miss']}")
        if not printed:
            logger.info("No tracked sequencer duties observed in this scan range.")
        logger.info("-" * 40)

    def run_realtime(self):
        """Real-time monitoring loop."""
        self.init_chain_params()
        self.check_validator_status()
        
        logger.info("Starting Real-time Monitor...")
        last_slot: Optional[int] = None
        
        # Filter for L2BlockProposed
        event_filter = self.rollup.events.L2BlockProposed.create_filter(from_block='latest')
        
        while True:
            try:
                current_l1 = self.w3.eth.get_block('latest')
                ts = current_l1['timestamp']
                
                # Calculate Aztec time
                current_slot = (ts - self.config['genesis_time']) // self.config['slot_duration']
                current_epoch = current_slot // self.config['epoch_duration']

                slot_changed = current_slot != last_slot

                if slot_changed:
                    needs_prediction = (
                        self.last_predicted_epoch != current_epoch or
                        self.next_duty_slot is None or
                        current_slot > self.next_duty_slot
                    )

                    if needs_prediction:
                        self.predict_upcoming_duties(current_epoch, current_slot, ts)
                        self.last_predicted_epoch = current_epoch

                    # Proposal ETA
                    next_proposal = "N/A"
                    if self.next_duty_slot_ts is not None:
                        next_proposal = format_duration(int(max(0, self.next_duty_slot_ts - ts)))

                    # Attestation status/ETA
                    attest_info = "Attest: none"
                    if self.attest_current_epoch:
                        attest_info = "Attest: current epoch"
                    elif self.next_attest_ts is not None and self.next_attest_epoch is not None:
                        attest_info = f"Attest in: {format_duration(int(max(0, self.next_attest_ts - ts)))} (Epoch {self.next_attest_epoch})"

                    logger.info(f"[Heartbeat] L1: {current_l1['number']} | Epoch: {current_epoch} | Slot: {current_slot} | Next proposal in: {next_proposal} | {attest_info}")
                    self.check_validator_status()
                    self.check_missed_slots(current_slot)
                    last_slot = current_slot
                
                # Process New Logs
                new_entries = event_filter.get_new_entries()
                for log in new_entries:
                    self.analyze_block_perf(log['args']['blockNumber'], log['transactionHash'])
                    
                # Sleep until the next slot boundary to stay aligned with slot cadence
                next_slot_ts = self.config['genesis_time'] + ((current_slot + 1) * self.config['slot_duration'])
                sleep_for = max(0, next_slot_ts - ts)
                time.sleep(sleep_for)
                
            except KeyboardInterrupt:
                logger.info("Stopping...")
                break
            except Exception as e:
                logger.error(f"Loop error: {e}")
                time.sleep(5)

# --- Entry Point ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aztecanary Monitor")
    parser.add_argument("-scan", help="Historical scan lookback (e.g., '100', '24h', '2e', 'e984')", default=None)
    args = parser.parse_args()

    targets = parse_targets(TARGETS_ENV)
    if not targets:
        logger.error("TARGETS is required. Set TARGETS env var (comma-separated addresses).")
        sys.exit(1)

    canary = Aztecanary(targets)

    if args.scan:
        canary.run_scan(args.scan)
    else:
        canary.run_realtime()
