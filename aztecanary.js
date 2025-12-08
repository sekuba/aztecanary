/**
 * aztecanary.js
 * 
 * A minimal, efficient monitor for Aztec Sequencers.
 * Tracks Committee membership, Proposal duties, Attestation performance, and Validator health.
 * 
 * Usage: 
 *   export RPC_URL="http://192.168.1.199:8545"
 *   export TARGETS="0x123...,0x456..."
 *   node aztecanary.js
 */

const { ethers } = require("ethers");

// --- Configuration ---
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8545";
const POLL_INTERVAL_MS = 12000; // ~1 Ethereum block
const HEALTH_CHECK_INTERVAL_BLOCKS = 50; 

// Comma separated addresses to watch
const TARGET_SEQUENCERS = new Set(
    (process.env.TARGETS || "").split(",").map(a => a.trim().toLowerCase()).filter(a => a)
);

// --- Contract Constants ---
// Rollup Proxy Address (from provided source)
const ROLLUP_ADDRESS = "0x603bb2c05D474794ea97805e8De69bCcFb3bCA12";

// Minimal ABI fragments required for monitoring
const ROLLUP_ABI = [
    // Events
    "event L2BlockProposed(uint256 indexed blockNumber, bytes32 indexed archive, bytes32[] versionedBlobHashes)",
    // Views
    "function getAttesterView(address _attester) view returns (tuple(uint8 status, uint256 effectiveBalance, tuple(uint256 withdrawalId, uint256 amount, uint256 exitableAt, address recipientOrWithdrawer, bool isRecipient, bool exists) exit, tuple(tuple(uint256 x, uint256 y) publicKey, address withdrawer) config))",
    "function getCurrentEpoch() view returns (uint256)",
    "function getEpochCommittee(uint256 _epoch) view returns (address[])",
    "function getSampleSeedAt(uint256 _ts) view returns (uint256)",
    "function getTimestampForSlot(uint256 _slotNumber) view returns (uint256)",
    "function getEpochAtSlot(uint256 _slotNumber) view returns (uint256)",
    "function getSlotAt(uint256 _ts) view returns (uint256)",
    "function getEpochDuration() view returns (uint256)",
    "function getSlotDuration() view returns (uint256)",
    "function getGenesisTime() view returns (uint256)",
    // Propose function for decoding calldata
    "function propose(tuple(bytes32 archive, tuple(tuple(bytes32 root, uint32 nextAvailableLeafIndex) l1ToL2MessageTree, tuple(tuple(bytes32 root, uint32 nextAvailableLeafIndex) noteHashTree, tuple(bytes32 root, uint32 nextAvailableLeafIndex) nullifierTree, tuple(bytes32 root, uint32 nextAvailableLeafIndex) publicDataTree) partialStateReference) stateReference, tuple(int256 feeAssetPriceModifier) oracleInput, tuple(bytes32 lastArchiveRoot, tuple(bytes32 blobsHash, bytes32 inHash, bytes32 outHash) contentCommitment, uint256 slotNumber, uint256 timestamp, address coinbase, bytes32 feeRecipient, tuple(uint128 feePerDaGas, uint128 feePerL2Gas) gasFees, uint256 totalManaUsed) header) _args, tuple(bytes signatureIndices, bytes signaturesOrAddresses) _attestations, address[] _signers, tuple(uint8 v, bytes32 r, bytes32 s) _attestationsAndSignersSignature, bytes _blobInput)"
];

// --- State Cache ---
const state = {
    epochDuration: 0n,
    slotDuration: 0n,
    genesisTime: 0n,
    currentEpoch: -1n,
    committee: [], // Array of addresses
    seed: 0n, // Randomness seed for current epoch
    lastProcessedL2Block: 0n
};

// --- Helpers ---

function log(type, message, data = {}) {
    const timestamp = new Date().toISOString();
    console.log(JSON.stringify({ timestamp, type, message, ...data }));
}

// Replicates ValidatorSelectionLib.computeProposerIndex
function computeProposerIndex(epoch, slot, seed, committeeSize) {
    if (committeeSize === 0n) return 0n;
    // solidity: uint256(keccak256(abi.encode(_epoch, _slot, _seed))) % _size
    const packed = ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256", "uint256"],
        [epoch, slot, seed]
    );
    const hash = ethers.keccak256(packed);
    const bigHash = BigInt(hash);
    return bigHash % BigInt(committeeSize);
}

// Decodes the bitmap from CommitteeAttestations
function checkAttestation(signatureIndicesBytes, index) {
    // signatureIndices is bytes. index is the committee index.
    // logic from AttestationLib.isSignature:
    // uint256 byteIndex = _index / 8;
    // uint256 shift = 7 - (_index % 8);
    // return (uint8(_attestations.signatureIndices[byteIndex]) >> shift) & 1 == 1;

    const byteIndex = Math.floor(index / 8);
    const shift = 7 - (index % 8);
    
    const bytesBuffer = ethers.getBytes(signatureIndicesBytes);
    
    if (byteIndex >= bytesBuffer.length) return false;
    
    const byte = bytesBuffer[byteIndex];
    return ((byte >> shift) & 1) === 1;
}

// --- Main Monitor Class ---

class Aztecanary {
    constructor() {
        this.provider = new ethers.JsonRpcProvider(RPC_URL);
        this.rollup = new ethers.Contract(ROLLUP_ADDRESS, ROLLUP_ABI, this.provider);
        this.iface = new ethers.Interface(ROLLUP_ABI);
    }

    async init() {
        log("INFO", "Initializing Aztecanary...");
        // Fetch static chain params once
        this.state = {
            ...state,
            epochDuration: await this.rollup.getEpochDuration(),
            slotDuration: await this.rollup.getSlotDuration(),
            genesisTime: await this.rollup.getGenesisTime()
        };
        log("INFO", "Chain Params Loaded", { 
            epochDuration: this.state.epochDuration.toString(),
            slotDuration: this.state.slotDuration.toString() 
        });

        // Initial Health Check
        await this.checkValidatorStatus();
    }

    async checkValidatorStatus() {
        if (TARGET_SEQUENCERS.size === 0) return;
        
        log("INFO", "Running Health Check on Validators");
        for (const addr of TARGET_SEQUENCERS) {
            try {
                const view = await this.rollup.getAttesterView(addr);
                const statusEnum = ["NONE", "VALIDATING", "ZOMBIE", "EXITING"];
                const status = statusEnum[Number(view.status)] || "UNKNOWN";
                const balance = ethers.formatEther(view.effectiveBalance);

                if (status !== "VALIDATING") {
                    log("ALERT", `Validator ${addr} is not VALIDATING`, { status, balance });
                } else {
                    log("HEALTH", `Validator ${addr} OK`, { status, balance });
                }
            } catch (e) {
                log("ERROR", `Failed checkValidatorStatus for ${addr}`, { error: e.message });
            }
        }
    }

    async updateEpochState(blockNumber, timestamp) {
        try {
            // Calculate current slot/epoch locally to save RPC calls
            const ts = BigInt(timestamp);
            const slot = (ts - this.state.genesisTime) / this.state.slotDuration;
            const epoch = slot / this.state.epochDuration;

            // If epoch changed, fetch new committee and randomness
            if (epoch !== this.state.currentEpoch) {
                log("INFO", `Epoch Transition: ${this.state.currentEpoch} -> ${epoch}`);
                
                // Fetch Committee
                const committee = await this.rollup.getEpochCommittee(epoch);
                const normalizedCommittee = committee.map(a => a.toLowerCase());
                
                // Fetch Seed
                const seed = await this.rollup.getSampleSeedAt(ts);

                this.state.currentEpoch = epoch;
                this.state.committee = normalizedCommittee;
                this.state.seed = seed;

                // Check Membership
                for (const target of TARGET_SEQUENCERS) {
                    if (normalizedCommittee.includes(target)) {
                        log("INFO", `Target ${target} is in Committee for Epoch ${epoch}`);
                    } else {
                        log("WARN", `Target ${target} is NOT in Committee for Epoch ${epoch}`);
                    }
                }
            }
            return { slot, epoch };
        } catch (e) {
            log("ERROR", "Failed to update epoch state", { error: e.message });
            return null;
        }
    }

    async processProposedBlock(logEvent, txHash) {
        try {
            const tx = await this.provider.getTransaction(txHash);
            if (!tx) return;

            const decoded = this.iface.parseTransaction({ data: tx.data, value: tx.value });
            if (!decoded || decoded.name !== 'propose') return;

            const args = decoded.args;
            const header = args._args.header;
            const attestations = args._attestations;

            const l2BlockNum = logEvent.args[0]; // From event args
            const slot = header.slotNumber;
            
            // 1. Verify Proposer Duty
            const committeeSize = BigInt(this.state.committee.length);
            const expectedProposerIndex = computeProposerIndex(this.state.currentEpoch, slot, this.state.seed, committeeSize);
            const expectedProposer = this.state.committee[Number(expectedProposerIndex)];
            const actualProposer = tx.from.toLowerCase();

            // Monitor Proposer
            if (TARGET_SEQUENCERS.has(expectedProposer)) {
                if (expectedProposer === actualProposer) {
                    log("PERF_SUCCESS", `Target ${expectedProposer} proposed block ${l2BlockNum} (Slot ${slot})`);
                } else {
                    log("PERF_MISS", `Target ${expectedProposer} missed proposal for slot ${slot}. Proposed by ${actualProposer}`);
                }
            }

            // 2. Verify Attestation Duty (For the PREVIOUS block)
            // Attestations in block N are for block N-1. 
            // Note: The committee for the attestation is based on the epoch of slot N-1.
            // For simplicity in this script, we assume N and N-1 are in same epoch usually.
            // Handling epoch boundary crossing for attestations requires caching previous epoch committee.
            // We use current committee for simplicity, but strictly correct impl needs history if boundary crossed.
            
            this.state.committee.forEach((validator, index) => {
                if (TARGET_SEQUENCERS.has(validator)) {
                    const didAttest = checkAttestation(attestations.signatureIndices, index);
                    if (didAttest) {
                        log("ATTEST_SUCCESS", `Target ${validator} attested to previous block`);
                    } else {
                        log("ATTEST_MISS", `Target ${validator} missed attestation for previous block`);
                    }
                }
            });

        } catch (e) {
            log("ERROR", "Failed to process block proposal", { error: e.message, tx: txHash });
        }
    }

    async start() {
        await this.init();

        this.provider.on("block", async (blockNumber) => {
            if (blockNumber % HEALTH_CHECK_INTERVAL_BLOCKS === 0) {
                await this.checkValidatorStatus();
            }

            const block = await this.provider.getBlock(blockNumber);
            const timeParams = await this.updateEpochState(blockNumber, block.timestamp);
            
            if (!timeParams) return;

            // Fetch Logs for this block specifically to catch L2BlockProposed
            const filter = {
                address: ROLLUP_ADDRESS,
                fromBlock: blockNumber,
                toBlock: blockNumber,
                topics: [
                    ethers.id("L2BlockProposed(uint256,bytes32,bytes32[])")
                ]
            };

            const logs = await this.provider.getLogs(filter);
            for (const l of logs) {
                const parsedLog = this.rollup.interface.parseLog(l);
                await this.processProposedBlock(parsedLog, l.transactionHash);
            }
        });

        log("INFO", `Monitoring started for ${TARGET_SEQUENCERS.size} targets on ${RPC_URL}`);
    }
}

// --- Bootstrap ---

if (TARGET_SEQUENCERS.size === 0) {
    console.error("Error: No TARGETS provided. Set TARGETS env var (comma separated addresses).");
    process.exit(1);
}

const canary = new Aztecanary();
canary.start().catch(e => {
    console.error("Fatal Error:", e);
    process.exit(1);
});

// export RPC_URL="http://192.168.1.199:8545"
// export TARGETS="0xYourSequencerAddress1,0xYourSequencerAddress2"