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
L1_BLOCK_TIME_SEC = 12
PROPOSE_SELECTOR = "0x48aeda19"
# Full propose param types (we only consume _signers)
PROPOSE_PARAM_TYPES = [
    "(bytes32,((bytes32,uint32),((bytes32,uint32),(bytes32,uint32),(bytes32,uint32))),(int256),(bytes32,(bytes32,bytes32,bytes32),uint256,uint256,address,bytes32,(uint128,uint128),uint256))",
    "(bytes,bytes)",
    "address[]",
    "(uint8,bytes32,bytes32)",
    "bytes",
]

# Minimal ABIs for interactions
ROLLUP_ABI = [
    # Events
    {"anonymous": False, "inputs": [{"indexed": True, "internalType": "uint256", "name": "blockNumber", "type": "uint256"}, {"indexed": True, "internalType": "bytes32", "name": "archive", "type": "bytes32"}, {"indexed": False, "internalType": "bytes32[]", "name": "versionedBlobHashes", "type": "bytes32[]"}], "name": "L2BlockProposed", "type": "event"},
    # View Functions
    {"inputs": [], "name": "getGenesisTime", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "getSlotDuration", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "getEpochDuration", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "getLagInEpochs", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "uint256", "name": "_epoch", "type": "uint256"}], "name": "getEpochCommittee", "outputs": [{"internalType": "address[]", "name": "", "type": "address[]"}], "stateMutability": "nonpayable", "type": "function"}, # Note: Non-view in source, but treated as view for data fetching usually
    {"inputs": [{"internalType": "uint256", "name": "_ts", "type": "uint256"}], "name": "getSampleSeedAt", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "_attester", "type": "address"}], "name": "getAttesterView", "outputs": [{"components": [{"internalType": "uint8", "name": "status", "type": "uint8"}, {"internalType": "uint256", "name": "effectiveBalance", "type": "uint256"}], "internalType": "struct AttesterView", "name": "", "type": "tuple"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "uint256", "name": "_blockNumber", "type": "uint256"}], "name": "getBlock", "outputs": [{"components": [{"internalType": "bytes32", "name": "archive", "type": "bytes32"}, {"internalType": "bytes32", "name": "headerHash", "type": "bytes32"}, {"internalType": "bytes32", "name": "blobCommitmentsHash", "type": "bytes32"}, {"internalType": "bytes32", "name": "attestationsHash", "type": "bytes32"}, {"internalType": "bytes32", "name": "payloadDigest", "type": "bytes32"}, {"internalType": "uint256", "name": "slotNumber", "type": "uint256"}, {"components": [{"internalType": "uint256", "name": "excessMana", "type": "uint256"}, {"internalType": "uint256", "name": "manaUsed", "type": "uint256"}, {"internalType": "uint256", "name": "feeAssetPriceNumerator", "type": "uint256"}, {"internalType": "uint256", "name": "congestionCost", "type": "uint256"}, {"internalType": "uint256", "name": "proverCost", "type": "uint256"}], "internalType": "struct FeeHeader", "name": "feeHeader", "type": "tuple"}], "internalType": "struct BlockLog", "name": "", "type": "tuple"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "getCurrentProposer", "outputs": [{"internalType": "address", "name": "", "type": "address"}], "stateMutability": "nonpayable", "type": "function"},
    # Propose Function (for decoding tx input)
    {"inputs": [{"components": [{"components": [{"internalType": "uint256", "name": "slotNumber", "type": "uint256"}], "internalType": "struct ProposedHeader", "name": "header", "type": "tuple"}], "internalType": "struct ProposeArgs", "name": "_args", "type": "tuple"}, {"components": [{"internalType": "bytes", "name": "signatureIndices", "type": "bytes"}, {"internalType": "bytes", "name": "signaturesOrAddresses", "type": "bytes"}], "internalType": "struct CommitteeAttestations", "name": "_attestations", "type": "tuple"}, {"internalType": "address[]", "name": "_signers", "type": "address[]"}, {"components": [{"internalType": "uint8", "name": "v", "type": "uint8"}, {"internalType": "bytes32", "name": "r", "type": "bytes32"}, {"internalType": "bytes32", "name": "s", "type": "bytes32"}], "internalType": "struct ECDSAData", "name": "_attestationsAndSignersSignature", "type": "tuple"}, {"internalType": "bytes", "name": "_blobInput", "type": "bytes"}], "name": "propose", "type": "function"}
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
    if not raw_targets:
        return set()
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
        """Fetches immutable chain parameters."""
        logger.info("Initializing chain parameters...")
        if not self.w3.is_connected():
            logger.error("Could not connect to RPC")
            sys.exit(1)

        try:
            self.config = {
                "genesis_time": self.rollup.functions.getGenesisTime().call(),
                "slot_duration": self.rollup.functions.getSlotDuration().call(),
                "epoch_duration": self.rollup.functions.getEpochDuration().call(),
                "lag": self.rollup.functions.getLagInEpochs().call()
            }
            
            logger.info(f"Chain Params: EpochDur={self.config['epoch_duration']} slots, "
                        f"SlotDur={self.config['slot_duration']}s, Lag={self.config['lag']} epochs")
            
            if not self.targets:
                logger.warning("No TARGETS configured. Monitoring passive chain health only.")
            else:
                logger.info(f"Tracking {len(self.targets)} sequencers: {', '.join(self.targets)}...")
                
        except Exception as e:
            logger.error(f"Failed to initialize chain params: {e}")
            sys.exit(1)

    def get_epoch_data(self, epoch: int) -> Optional[Dict]:
        """Fetches or retrieves cached committee and seed for an epoch."""
        if epoch in self.epoch_cache:
            return self.epoch_cache[epoch]

        try:
            # Calculate timestamp for sampling based on lag (simplified from Solidity logic)
            # We use the seedAt function which handles the lag internally if we pass the *start* of the epoch?
            # Actually, ValidatorSelectionLib.getSampleSeedAt takes timestamp.
            # To be safe and mimic JS behavior, we derive specific TS.
            # TS = Genesis + (Epoch * EpochDur * SlotDur)
            ts = self.config['genesis_time'] + (epoch * self.config['epoch_duration'] * self.config['slot_duration'])
            
            # Using multicall logic here implies sending multiple requests, we'll do sequential for minimal deps
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
            return None

    def check_validator_status(self):
        """Polls the status of tracked validators."""
        if not self.targets: return
        
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
        """Decodes a propose call payload to extract signers."""
        if call_data[:4].hex() != PROPOSE_SELECTOR[2:]:
            return None

        try:
            decoded = decode(PROPOSE_PARAM_TYPES, call_data[4:])
            signers = [to_checksum_address(s) for s in decoded[2]]
            return {"_signers": signers}
        except Exception as e:
            logger.error(f"decode_propose_call failure: {e}", exc_info=True)
            return None

    def decode_propose_tx(self, tx) -> Optional[Dict]:
        """
        Decodes a transaction to find the `propose` call arguments.
        Handles Multicall3 aggregate3 (0x82ad56cb) wrapping propose.
        """
        input_hex = tx.input.hex()
        selector = f"0x{input_hex[:8]}"

        # Multicall3 aggregate3
        try:
            if selector == "0x82ad56cb":
                raw_data = bytes.fromhex(input_hex[8:])  # strip selector (4 bytes)
                decoded_calls = decode(['(address,bool,bytes)[]'], raw_data)[0]

                for (target, _, call_data) in decoded_calls:
                    if to_checksum_address(target) == ROLLUP_ADDRESS:
                        propose = self._decode_propose_call(call_data)
                        if propose:
                            return propose
        except Exception:
            logger.error(f"decode_propose_tx failure selector={selector} len={len(tx.input)} tx={tx.hash.hex()}", exc_info=True)
            
        return None

    def analyze_block_perf(self, l2_block_num: int, tx_hash: str, context: str = "REALTIME") -> Tuple[Optional[str], List[str]]:
        """
        Analyzes a specific L2 block proposal for proposer correctness and attestations.
        Returns (ProposerAddress, List[MissedAttesters]).
        """
        try:
            block_view = self.rollup.functions.getBlock(l2_block_num).call()
            slot = block_view[5]  # slotNumber
            self.processed_slots.add(slot)

            tx = self.w3.eth.get_transaction(tx_hash)
            args = self.decode_propose_tx(tx)
            if not args:
                logger.error(f"[{context}] Could not decode propose tx for L2 block {l2_block_num}; duty checks incomplete")
                return None, []

            # Extract from tx args and on-chain block view
            signers = [to_checksum_address(s) for s in args['_signers']]
            
            epoch = slot // self.config['epoch_duration']
            epoch_data = self.get_epoch_data(epoch)
            
            if not epoch_data or not epoch_data.get("committee"):
                return None, []

            committee = epoch_data['committee']
            committee_size = len(committee)

            expected_proposer = None
            if committee_size > 0:
                expected_idx = compute_proposer_index(epoch, slot, epoch_data['seed'], committee_size)
                expected_proposer = committee[expected_idx]
                if expected_proposer in self.targets:
                    logger.info(f"[{context}] DUTY:PROPOSAL_OK - Block {l2_block_num} (Slot {slot}) proposed by tracked {expected_proposer[:8]}")
        
            missed_attesters = []

            # Verify attestations using signer list only
            for _, validator in enumerate(committee):
                if validator in self.targets:
                    if validator not in signers:
                        logger.warning(f"[{context}] DUTY:ATTEST_MISS - {validator[:8]} missed attestation for Block {l2_block_num}. txhash={tx_hash.hex()}")
                        missed_attesters.append(validator)
            
            return expected_proposer, missed_attesters

        except Exception as e:
            logger.error(f"[{context}] Error analyzing block {l2_block_num}: {e}")
            return None, []

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
            if not epoch_data or not epoch_data['committee']:
                continue
                
            idx = compute_proposer_index(epoch, s, epoch_data['seed'], len(epoch_data['committee']))
            expected_proposer = epoch_data['committee'][idx]
            
            if expected_proposer in self.targets:
                logger.warning(f"[REALTIME] DUTY:PROPOSAL_MISS - Slot {s} missed by tracked {expected_proposer}")
        
        self.last_checked_slot = current_slot

    def predict_upcoming_duties(self, start_epoch: int, current_slot: int):
        """
        Logs proposal duties for tracked sequencers for current epoch plus lag
        and tracks the nearest duty for heartbeat display.
        """
        lookahead_epochs = self.config['lag']
        summaries = []
        nearest: Optional[Dict[str, Any]] = None
        now_ts = time.time()
        attest_current = False
        next_attest_epoch: Optional[int] = None
        next_attest_ts: Optional[float] = None

        for e in range(start_epoch, start_epoch + lookahead_epochs + 1):
            data = self.get_epoch_data(e)
            if not data or not data.get("committee"):
                continue

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
        
        # Parse lookback
        blocks_to_scan = 0
        if lookback_str.lower().endswith("h"):
            hours = int(lookback_str[:-1])
            blocks_to_scan = (hours * 3600) // L1_BLOCK_TIME_SEC
        elif lookback_str.lower().endswith("d"):
            days = int(lookback_str[:-1])
            blocks_to_scan = (days * 86400) // L1_BLOCK_TIME_SEC
        else:
            blocks_to_scan = int(lookback_str)

        current_l1 = self.w3.eth.block_number
        from_block = max(0, current_l1 - blocks_to_scan)
        
        logger.info(f"Starting Historical Scan from L1 Block {from_block} to {current_l1} (~{blocks_to_scan} blocks)")
        
        # 1. Fetch Logs
        logs = self.rollup.events.L2BlockProposed.get_logs(from_block=from_block, to_block=current_l1)
        logger.info(f"Found {len(logs)} L2 Blocks proposed in range.")
        
        missed_props = 0
        missed_attests = 0
        
        for log in logs:
            l2_block = log['args']['blockNumber']
            _, misses = self.analyze_block_perf(l2_block, log['transactionHash'], context="HISTORY")
            if misses:
                missed_attests += len(misses)
                
        # To check for missed proposals in history, we need to reconstruct the full slot map
        # This is expensive for long ranges, so strictly checking "observed" blocks for attestations 
        # and checking if any observed blocks were supposed to be ours but weren't (difficult without full map).
        # We will iterate known logs.
        
        # Simplified Audit Summary
        logger.info("-" * 40)
        logger.info(f"Scan Complete. Observed L2 Blocks: {len(logs)}")
        logger.info(f"Attestation Misses (Tracked): {missed_attests}")
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
                        self.predict_upcoming_duties(current_epoch, current_slot)
                        self.last_predicted_epoch = current_epoch

                    # Proposal ETA
                    next_proposal = "N/A"
                    if self.next_duty_slot_ts is not None:
                        next_proposal = format_duration(int(max(0, self.next_duty_slot_ts - time.time())))

                    # Attestation status/ETA
                    attest_info = "Attest: none"
                    if self.attest_current_epoch:
                        attest_info = "Attest: current epoch"
                    elif self.next_attest_ts is not None and self.next_attest_epoch is not None:
                        attest_info = f"Attest in: {format_duration(int(max(0, self.next_attest_ts - time.time())))} (Epoch {self.next_attest_epoch})"

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
                sleep_for = max(0, next_slot_ts - time.time())
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
    parser.add_argument("-scan", help="Historical scan lookback (e.g., '100', '24h', '1d')", default=None)
    args = parser.parse_args()

    targets = parse_targets(TARGETS_ENV)
    if not targets:
        logger.warning("No TARGETS environment variable set. Running in passive mode.")

    canary = Aztecanary(targets)

    if args.scan:
        canary.run_scan(args.scan)
    else:
        canary.run_realtime()
