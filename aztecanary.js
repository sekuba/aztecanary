/**
 * aztecanary.js
 * 
 * Monitoring for Aztec Sequencers.
 * Tracks: Validator Status, Committee Membership (Current + Lookahead), 
 * Proposer Schedules, and Proposal/Attestation Performance.
 * 
 * Usage: 
 *   export RPC_URL="http://192.168.1.199:8545"
 *   export TARGETS="0x123...,0x456..."
 *   node aztecanary.js
 */

const { ethers } = require("ethers");

// --- Configuration ---
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8545";
// Check validator status every N blocks
const HEALTH_CHECK_INTERVAL_BLOCKS = 50; 

// Comma separated addresses to watch
const TARGET_SEQUENCERS = new Set(
    (process.env.TARGETS || "").split(",").map(a => a.trim().toLowerCase()).filter(a => a)
);

// --- Contract Constants ---
const ROLLUP_ADDRESS = "0x603bb2c05D474794ea97805e8De69bCcFb3bCA12";

const ROLLUP_ABI = [
    // Events
    "event L2BlockProposed(uint256 indexed blockNumber, bytes32 indexed archive, bytes32[] versionedBlobHashes)",
    // Views
    "function getAttesterView(address _attester) view returns (tuple(uint8 status, uint256 effectiveBalance, tuple(uint256 withdrawalId, uint256 amount, uint256 exitableAt, address recipientOrWithdrawer, bool isRecipient, bool exists) exit, tuple(tuple(uint256 x, uint256 y) publicKey, address withdrawer) config))",
    "function getCurrentEpoch() view returns (uint256)",
    "function getEpochCommittee(uint256 _epoch) view returns (address[])",
    "function getSampleSeedAt(uint256 _ts) view returns (uint256)",
    "function getLagInEpochs() view returns (uint256)",
    "function getEpochDuration() view returns (uint256)",
    "function getSlotDuration() view returns (uint256)",
    "function getGenesisTime() view returns (uint256)",
    // Propose function for decoding calldata
    "function propose(tuple(bytes32 archive, tuple(tuple(bytes32 root, uint32 nextAvailableLeafIndex) l1ToL2MessageTree, tuple(tuple(bytes32 root, uint32 nextAvailableLeafIndex) noteHashTree, tuple(bytes32 root, uint32 nextAvailableLeafIndex) nullifierTree, tuple(bytes32 root, uint32 nextAvailableLeafIndex) publicDataTree) partialStateReference) stateReference, tuple(int256 feeAssetPriceModifier) oracleInput, tuple(bytes32 lastArchiveRoot, tuple(bytes32 blobsHash, bytes32 inHash, bytes32 outHash) contentCommitment, uint256 slotNumber, uint256 timestamp, address coinbase, bytes32 feeRecipient, tuple(uint128 feePerDaGas, uint128 feePerL2Gas) gasFees, uint256 totalManaUsed) header) _args, tuple(bytes signatureIndices, bytes signaturesOrAddresses) _attestations, address[] _signers, tuple(uint8 v, bytes32 r, bytes32 s) _attestationsAndSignersSignature, bytes _blobInput)"
];

// --- Helpers ---

function log(type, message, data = {}) {
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), type, message, ...data }));
}

// Replicates ValidatorSelectionLib.computeProposerIndex logic locally
// This allows us to predict every single slot in an epoch without making 32 RPC calls
function computeProposerIndex(epoch, slot, seed, committeeSize) {
    if (committeeSize === 0n) return 0n;
    // solidity: uint256(keccak256(abi.encode(_epoch, _slot, _seed))) % _size
    const packed = ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256", "uint256"],
        [epoch, slot, seed]
    );
    return BigInt(ethers.keccak256(packed)) % BigInt(committeeSize);
}

// Decodes the bitmap from CommitteeAttestations
function checkAttestation(signatureIndicesBytes, index) {
    const byteIndex = Math.floor(index / 8);
    const shift = 7 - (index % 8);
    const bytesBuffer = ethers.getBytes(signatureIndicesBytes);
    if (byteIndex >= bytesBuffer.length) return false;
    return ((bytesBuffer[byteIndex] >> shift) & 1) === 1;
}

// --- Main Monitor Class ---

class Aztecanary {
    constructor() {
        this.provider = new ethers.JsonRpcProvider(RPC_URL);
        this.rollup = new ethers.Contract(ROLLUP_ADDRESS, ROLLUP_ABI, this.provider);
        this.iface = new ethers.Interface(ROLLUP_ABI);
        
        // State
        this.config = {};
        // Cache processed epochs to avoid spamming the schedule
        this.processedEpochs = new Set();
        // Cache committee info: epoch -> { committee: [], seed: BigInt }
        this.epochCache = new Map();
    }

    async init() {
        log("INFO", "Initializing...");
        const [epochDuration, slotDuration, genesisTime, lag] = await Promise.all([
            this.rollup.getEpochDuration(),
            this.rollup.getSlotDuration(),
            this.rollup.getGenesisTime(),
            this.rollup.getLagInEpochs()
        ]);

        this.config = { epochDuration, slotDuration, genesisTime, lag };
        
        log("CONFIG", "Chain Parameters Loaded", { 
            epochDuration: epochDuration.toString(), 
            slotDuration: slotDuration.toString(),
            lag: lag.toString()
        });

        // Run initial checks immediately (don't wait for next block)
        await this.checkValidatorStatus();
        const block = await this.provider.getBlock("latest");
        await this.handleBlock(block);
    }

    async checkValidatorStatus() {
        if (TARGET_SEQUENCERS.size === 0) return;
        
        for (const addr of TARGET_SEQUENCERS) {
            try {
                const view = await this.rollup.getAttesterView(addr);
                const statusEnum = ["NONE", "VALIDATING", "ZOMBIE", "EXITING"];
                const status = statusEnum[Number(view.status)] || "UNKNOWN";
                const balance = ethers.formatEther(view.effectiveBalance);

                if (status !== "VALIDATING") {
                    log("ALERT", `Validator ${addr} is not VALIDATING`, { status, balance });
                }
            } catch (e) {
                log("ERROR", `Failed status check for ${addr}`, { error: e.message });
            }
        }
    }

    // Fetches committee/seed for an epoch if not cached
    async ensureEpochData(epoch) {
        if (this.epochCache.has(epoch)) return this.epochCache.get(epoch);

        try {
            // We need a timestamp that falls within this epoch to fetch the seed
            // Start of epoch timestamp:
            const ts = this.config.genesisTime + (BigInt(epoch) * this.config.epochDuration * this.config.slotDuration);
            
            const [committee, seed] = await Promise.all([
                this.rollup.getEpochCommittee(epoch),
                this.rollup.getSampleSeedAt(ts)
            ]);

            const data = {
                committee: committee.map(a => a.toLowerCase()),
                seed: seed
            };
            
            this.epochCache.set(epoch, data);
            
            // Cleanup old cache
            if (this.epochCache.size > 10) {
                const oldest = Array.from(this.epochCache.keys()).sort()[0];
                this.epochCache.delete(oldest);
            }
            
            return data;
        } catch (e) {
            log("ERROR", `Could not fetch data for Epoch ${epoch}`, { error: e.message });
            return null;
        }
    }

    async predictDuties(currentEpoch) {
        // Look ahead: Current + Lag
        // If Lag is 2, and we are in epoch 100.
        // We know duties for 100, 101, 102.
        const maxEpoch = BigInt(currentEpoch) + this.config.lag;

        for (let e = BigInt(currentEpoch); e <= maxEpoch; e++) {
            const epochKey = e.toString();
            if (this.processedEpochs.has(epochKey)) continue;

            const data = await this.ensureEpochData(e);
            if (!data) continue;

            // 1. Check Committee Membership
            const myValidators = [];
            data.committee.forEach((val, idx) => {
                if (TARGET_SEQUENCERS.has(val)) myValidators.push({ val, idx });
            });

            if (myValidators.length === 0) {
                log("INFO", `Epoch ${e}: No targets in committee`);
                this.processedEpochs.add(epochKey);
                continue;
            }

            log("COMMITTEE", `Epoch ${e}: Targets in committee`, { count: myValidators.length, validators: myValidators.map(v => v.val) });

            // 2. Calculate Proposer Duties for this Epoch
            // Iterate all slots in this epoch
            const startSlot = e * this.config.epochDuration;
            let dutiesFound = 0;

            for (let i = 0n; i < this.config.epochDuration; i++) {
                const slot = startSlot + i;
                const proposerIndex = computeProposerIndex(e, slot, data.seed, BigInt(data.committee.length));
                const proposer = data.committee[Number(proposerIndex)];

                if (TARGET_SEQUENCERS.has(proposer)) {
                    dutiesFound++;
                    // Calculate Wall Time
                    const ts = this.config.genesisTime + (slot * this.config.slotDuration);
                    const date = new Date(Number(ts) * 1000).toLocaleString();
                    
                    log("DUTY", `Proposer Duty Found`, {
                        epoch: e.toString(),
                        slot: slot.toString(),
                        validator: proposer,
                        time: date
                    });
                }
            }

            if (dutiesFound === 0) {
                log("INFO", `Epoch ${e}: In committee, but no proposer duties assigned`);
            }

            this.processedEpochs.add(epochKey);
        }
    }

    async checkPerformance(logEvent, txHash, epochData) {
        try {
            const tx = await this.provider.getTransaction(txHash);
            if (!tx) return;
            const decoded = this.iface.parseTransaction({ data: tx.data, value: tx.value });
            if (!decoded || decoded.name !== 'propose') return;

            const args = decoded.args;
            const header = args._args.header;
            const attestations = args._attestations;

            const slot = header.slotNumber;
            const l2BlockNum = logEvent.args[0];
            
            // 1. Proposer Check
            // Re-calculate who SHOULD have proposed
            const committeeSize = BigInt(epochData.committee.length);
            // Derive epoch from slot (in case block is from previous epoch boundary)
            const blockEpoch = slot / this.config.epochDuration;
            
            // If block epoch != current cached epoch data, fetch specific data (edge case)
            let blockEpochData = epochData;
            if (blockEpoch !== this.config.currentEpoch) {
                 blockEpochData = await this.ensureEpochData(blockEpoch);
            }

            if (blockEpochData) {
                const expectedIndex = computeProposerIndex(blockEpoch, slot, blockEpochData.seed, committeeSize);
                const expectedProposer = blockEpochData.committee[Number(expectedIndex)];
                
                if (TARGET_SEQUENCERS.has(expectedProposer)) {
                    // In Aztec propose(), the sender is verified by signature in attestations if via relay
                    // But usually for monitoring tx.from is good enough indication of who paid/sent it
                    // Strictly, we should check _signers array if available, but let's check tx.from first
                    const actualProposer = tx.from.toLowerCase();
                    
                    if (expectedProposer === actualProposer) {
                        log("PERF_SUCCESS", `Block ${l2BlockNum} proposed by target ${expectedProposer}`);
                    } else {
                        log("PERF_MISS", `Block ${l2BlockNum} MISSED by ${expectedProposer}. Proposed by ${actualProposer}`);
                    }
                }

                // 2. Attestation Check (Did targets sign this block?)
                // Attestations in this tx are for the *previous* block.
                // We check if our targets (who are in the committee) signed off on this payload.
                blockEpochData.committee.forEach((validator, index) => {
                    if (TARGET_SEQUENCERS.has(validator)) {
                        const didAttest = checkAttestation(attestations.signatureIndices, index);
                        if (didAttest) {
                            // log("ATTEST_OK", `Target ${validator} attested`); // Spammy, maybe verify only on error or summary
                        } else {
                            log("ATTEST_MISS", `Target ${validator} failed to attest to block ${l2BlockNum}`);
                        }
                    }
                });
            }
        } catch (e) {
            log("ERROR", "Perf check failed", { error: e.message });
        }
    }

    async handleBlock(block) {
        try {
            const ts = BigInt(block.timestamp);
            const slot = (ts - this.config.genesisTime) / this.config.slotDuration;
            const epoch = slot / this.config.epochDuration;

            // 1. Log Heartbeat
            if (Number(block.number) % 10 === 0) {
                console.log(`[Heartbeat] L1: ${block.number} | Epoch: ${epoch} | Slot: ${slot}`);
            }

            // 2. Update Epoch Data (Committee/Seed) if needed
            const epochData = await this.ensureEpochData(epoch);
            if (!epochData) return;

            this.config.currentEpoch = epoch; // Update tracker

            // 3. Predict Future Duties (Current -> Lag)
            await this.predictDuties(epoch);

            // 4. Process Events (Proposals)
            const filter = {
                address: ROLLUP_ADDRESS,
                fromBlock: block.number,
                toBlock: block.number,
                topics: [ ethers.id("L2BlockProposed(uint256,bytes32,bytes32[])") ]
            };

            const logs = await this.provider.getLogs(filter);
            for (const l of logs) {
                const parsedLog = this.rollup.interface.parseLog(l);
                await this.checkPerformance(parsedLog, l.transactionHash, epochData);
            }

        } catch (e) {
            log("ERROR", "Block handling failed", { error: e.message });
        }
    }

    async start() {
        await this.init();

        this.provider.on("block", async (blockNumber) => {
            // Periodic Health Check
            if (blockNumber % HEALTH_CHECK_INTERVAL_BLOCKS === 0) {
                await this.checkValidatorStatus();
            }
            const block = await this.provider.getBlock(blockNumber);
            await this.handleBlock(block);
        });

        log("INFO", `Monitoring active for ${TARGET_SEQUENCERS.size} targets`);
    }
}

// --- Bootstrap ---
if (TARGET_SEQUENCERS.size === 0) {
    console.error("Error: Set TARGETS env var (comma separated addresses).");
    process.exit(1);
}

new Aztecanary().start().catch(console.error);