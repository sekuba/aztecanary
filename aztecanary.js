/**
 * aztecanary.js
 * 
 * A minimal, efficient monitor for Aztec Sequencers.
 * Features:
 * - Real-time Proposal/Attestation monitoring
 * - Predictive Scheduling (Current Epoch + Lag Lookahead)
 * - Historical verification of the current epoch (detects recent misses on startup)
 * - Validator Health Checks
 */

const { ethers } = require("ethers");

// --- Configuration ---
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8545";
const HEALTH_CHECK_INTERVAL_BLOCKS = 50; 

// Addresses to watch
const TARGET_SEQUENCERS = new Set(
    (process.env.TARGETS || "").split(",").map(a => a.trim().toLowerCase()).filter(a => a)
);

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
    "function getBlock(uint256 _blockNumber) view returns (tuple(bytes32 archive, bytes32 headerHash, bytes32 blobCommitmentsHash, bytes32 attestationsHash, bytes32 payloadDigest, uint256 slotNumber, tuple(uint256 excessMana, uint256 manaUsed, uint256 feeAssetPriceNumerator, uint256 congestionCost, uint256 proverCost) feeHeader))",
    // Decode helpers
    "function propose(tuple(bytes32 archive, tuple(tuple(bytes32 root, uint32 nextAvailableLeafIndex) l1ToL2MessageTree, tuple(tuple(bytes32 root, uint32 nextAvailableLeafIndex) noteHashTree, tuple(bytes32 root, uint32 nextAvailableLeafIndex) nullifierTree, tuple(bytes32 root, uint32 nextAvailableLeafIndex) publicDataTree) partialStateReference) stateReference, tuple(int256 feeAssetPriceModifier) oracleInput, tuple(bytes32 lastArchiveRoot, tuple(bytes32 blobsHash, bytes32 inHash, bytes32 outHash) contentCommitment, uint256 slotNumber, uint256 timestamp, address coinbase, bytes32 feeRecipient, tuple(uint128 feePerDaGas, uint128 feePerL2Gas) gasFees, uint256 totalManaUsed) header) _args, tuple(bytes signatureIndices, bytes signaturesOrAddresses) _attestations, address[] _signers, tuple(uint8 v, bytes32 r, bytes32 s) _attestationsAndSignersSignature, bytes _blobInput)"
];

// --- Helpers ---

function log(type, message, data = {}) {
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), type, message, ...data }));
}

function computeProposerIndex(epoch, slot, seed, committeeSize) {
    if (committeeSize === 0n) return 0n;
    const packed = ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256", "uint256"],
        [epoch, slot, seed]
    );
    return BigInt(ethers.keccak256(packed)) % BigInt(committeeSize);
}

function checkAttestation(signatureIndicesBytes, index) {
    const byteIndex = Math.floor(index / 8);
    const shift = 7 - (index % 8);
    const bytesBuffer = ethers.getBytes(signatureIndicesBytes);
    if (byteIndex >= bytesBuffer.length) return false;
    return ((bytesBuffer[byteIndex] >> shift) & 1) === 1;
}

// --- Main Class ---

class Aztecanary {
    constructor() {
        this.provider = new ethers.JsonRpcProvider(RPC_URL);
        this.rollup = new ethers.Contract(ROLLUP_ADDRESS, ROLLUP_ABI, this.provider);
        this.iface = new ethers.Interface(ROLLUP_ABI);
        
        this.config = {};
        this.processedEpochs = new Set();
        this.epochCache = new Map(); // Epoch -> { committee, seed }
    }

    async init() {
        log("INFO", "Initializing Aztecanary...");
        const [epochDuration, slotDuration, genesisTime, lag] = await Promise.all([
            this.rollup.getEpochDuration(),
            this.rollup.getSlotDuration(),
            this.rollup.getGenesisTime(),
            this.rollup.getLagInEpochs()
        ]);

        this.config = { epochDuration, slotDuration, genesisTime, lag };
        log("CONFIG", "Params Loaded", { 
            epochDuration: epochDuration.toString(), slotDuration: slotDuration.toString(), lag: lag.toString() 
        });

        // Startup checks
        await this.checkValidatorStatus();
        const block = await this.provider.getBlock("latest");
        await this.handleBlock(block); // This triggers current state prediction
        
        // Run historical verification for the current active epoch to catch misses that happened before we started
        await this.verifyCurrentEpochHistory(block);
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
                    log("ALERT", `Validator ${addr} status: ${status}`, { balance });
                }
            } catch (e) { log("ERROR", `Status check failed for ${addr}`); }
        }
    }

    async ensureEpochData(epoch) {
        if (this.epochCache.has(epoch)) return this.epochCache.get(epoch);
        try {
            const ts = this.config.genesisTime + (BigInt(epoch) * this.config.epochDuration * this.config.slotDuration);
            const [committee, seed] = await Promise.all([
                this.rollup.getEpochCommittee(epoch),
                this.rollup.getSampleSeedAt(ts)
            ]);
            const data = { committee: committee.map(a => a.toLowerCase()), seed };
            this.epochCache.set(epoch, data);
            return data;
        } catch (e) { return null; }
    }

    async predictDuties(currentEpoch, currentSlot) {
        const maxEpoch = BigInt(currentEpoch) + this.config.lag;

        for (let e = BigInt(currentEpoch); e <= maxEpoch; e++) {
            const epochKey = e.toString();
            // Only process once per epoch
            if (this.processedEpochs.has(epochKey)) continue;

            const data = await this.ensureEpochData(e);
            if (!data) continue;

            const isCurrent = e === BigInt(currentEpoch);
            const tag = isCurrent ? "CURRENT" : "FUTURE";

            // 1. Committee Check
            const inCommittee = data.committee.filter(val => TARGET_SEQUENCERS.has(val));
            if (inCommittee.length > 0) {
                log("COMMITTEE", `[${tag}] Epoch ${e}: Targets in committee`, { validators: inCommittee });
            } else {
                if (isCurrent) log("WARN", `[${tag}] Epoch ${e}: No targets in committee`);
            }

            // 2. Proposer Schedule
            const startSlot = e * this.config.epochDuration;
            for (let i = 0n; i < this.config.epochDuration; i++) {
                const slot = startSlot + i;
                // Don't log past duties for current epoch here, VerifyHistory handles that
                if (isCurrent && slot < currentSlot) continue; 

                const proposerIndex = computeProposerIndex(e, slot, data.seed, BigInt(data.committee.length));
                const proposer = data.committee[Number(proposerIndex)];

                if (TARGET_SEQUENCERS.has(proposer)) {
                    const ts = this.config.genesisTime + (slot * this.config.slotDuration);
                    log("DUTY", `[${tag}] Proposer Duty`, {
                        epoch: e.toString(), slot: slot.toString(), validator: proposer,
                        time: new Date(Number(ts) * 1000).toLocaleString()
                    });
                }
            }
            this.processedEpochs.add(epochKey);
        }
    }

    // SCANS the current epoch for missed blocks
    async verifyCurrentEpochHistory(currentL1Block) {
        try {
            const ts = BigInt(currentL1Block.timestamp);
            const currentSlot = (ts - this.config.genesisTime) / this.config.slotDuration;
            const epoch = currentSlot / this.config.epochDuration;
            const startSlot = epoch * this.config.epochDuration;

            log("AUDIT", `Verifying history for Epoch ${epoch} (Slots ${startSlot} to ${currentSlot})`);

            const data = await this.ensureEpochData(epoch);
            if (!data) return;

            // 1. Find all slots in the past of this epoch assigned to our targets
            const assignedSlots = new Map(); // Slot -> Validator
            for (let s = startSlot; s < currentSlot; s++) {
                const pIdx = computeProposerIndex(epoch, s, data.seed, BigInt(data.committee.length));
                const pAddr = data.committee[Number(pIdx)];
                if (TARGET_SEQUENCERS.has(pAddr)) {
                    assignedSlots.set(s.toString(), pAddr);
                }
            }

            if (assignedSlots.size === 0) return;

            // 2. Fetch L2BlockProposed logs for the last N blocks to find what actually happened
            // Approximation: 12s L1 blocks. 
            const slotsElapsed = Number(currentSlot - startSlot);
            const l1BlocksLookback = Math.ceil((slotsElapsed * Number(this.config.slotDuration)) / 12) + 50; 
            const fromBlock = currentL1Block.number - l1BlocksLookback;

            const filter = {
                address: ROLLUP_ADDRESS,
                fromBlock: fromBlock,
                toBlock: "latest",
                topics: [ ethers.id("L2BlockProposed(uint256,bytes32,bytes32[])") ]
            };

            const logs = await this.provider.getLogs(filter);
            const filledSlots = new Set();

            // 3. Check logs to see which slots were filled
            // We need to call getBlock to map L2BlockNum -> Slot
            // To be efficient, we'll do a batch of promises
            const checks = logs.map(async (l) => {
                const parsed = this.rollup.interface.parseLog(l);
                const blockNum = parsed.args[0];
                const blockData = await this.rollup.getBlock(blockNum);
                filledSlots.add(blockData.slotNumber.toString());
            });
            await Promise.all(checks);

            // 4. Compare
            for (const [slotStr, validator] of assignedSlots.entries()) {
                if (filledSlots.has(slotStr)) {
                    // Success is silent for history to reduce noise, or verify log level
                } else {
                    log("PERF_MISS", `HISTORICAL: Target ${validator} missed proposal for Slot ${slotStr} in current Epoch ${epoch}`);
                }
            }

        } catch (e) {
            log("ERROR", "History verification failed", { error: e.message });
        }
    }

    async processRealtimeBlock(logEvent, txHash, epochData) {
        try {
            const tx = await this.provider.getTransaction(txHash);
            if (!tx) return;
            const decoded = this.iface.parseTransaction({ data: tx.data, value: tx.value });
            if (!decoded || decoded.name !== 'propose') return;

            const slot = decoded.args._args.header.slotNumber;
            const l2BlockNum = logEvent.args[0];
            const actualProposer = tx.from.toLowerCase();
            
            // Derive info
            const blockEpoch = slot / this.config.epochDuration;
            let data = epochData;
            if (blockEpoch !== this.config.currentEpoch) data = await this.ensureEpochData(blockEpoch);

            if (!data) return;

            const expectedIndex = computeProposerIndex(blockEpoch, slot, data.seed, BigInt(data.committee.length));
            const expectedProposer = data.committee[Number(expectedIndex)];

            // Proposer Check
            if (TARGET_SEQUENCERS.has(expectedProposer)) {
                if (expectedProposer === actualProposer) {
                    log("PERF_SUCCESS", `Block ${l2BlockNum} proposed by ${expectedProposer}`);
                } else {
                    log("PERF_MISS", `Block ${l2BlockNum} MISSED by ${expectedProposer}. Taken by ${actualProposer}`);
                }
            }

            // Attestation Check (Previous Block)
            // Attestations included here are for the parent block.
            data.committee.forEach((validator, index) => {
                if (TARGET_SEQUENCERS.has(validator)) {
                    if (!checkAttestation(decoded.args._attestations.signatureIndices, index)) {
                        log("ATTEST_MISS", `Target ${validator} missed attestation for previous block`);
                    }
                }
            });

        } catch (e) { log("ERROR", "Realtime check failed", { error: e.message }); }
    }

    async handleBlock(block) {
        const ts = BigInt(block.timestamp);
        const slot = (ts - this.config.genesisTime) / this.config.slotDuration;
        const epoch = slot / this.config.epochDuration;

        if (Number(block.number) % 10 === 0) {
            console.log(`[Heartbeat] L1: ${block.number} | Epoch: ${epoch} | Slot: ${slot}`);
        }

        const data = await this.ensureEpochData(epoch);
        if (!data) return;

        this.config.currentEpoch = epoch;
        await this.predictDuties(epoch, slot);

        // Process Logs
        const logs = await this.provider.getLogs({
            address: ROLLUP_ADDRESS,
            fromBlock: block.number,
            toBlock: block.number,
            topics: [ ethers.id("L2BlockProposed(uint256,bytes32,bytes32[])") ]
        });

        for (const l of logs) {
            await this.processRealtimeBlock(this.rollup.interface.parseLog(l), l.transactionHash, data);
        }
    }

    async start() {
        await this.init();
        this.provider.on("block", async (bn) => {
            if (bn % HEALTH_CHECK_INTERVAL_BLOCKS === 0) await this.checkValidatorStatus();
            await this.handleBlock(await this.provider.getBlock(bn));
        });
        log("INFO", `Monitoring ${TARGET_SEQUENCERS.size} targets`);
    }
}

if (TARGET_SEQUENCERS.size === 0) { console.error("Error: Set TARGETS env var"); process.exit(1); }
new Aztecanary().start().catch(console.error);