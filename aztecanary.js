/**
 * aztecanary.js v6
 * 
 * Monitor for Aztec Sequencers.
 * 
 * Changelog:
 * - Added explicit tracking logs on startup.
 * - Added "PERF_CHECK" summary logs for visibility.
 * - Enabled verbose Attestation logs (OK/MISS).
 * - Refined committee matching logic.
 */

const { ethers } = require("ethers");

// --- Configuration ---
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8545";
const HEALTH_CHECK_INTERVAL_BLOCKS = 50; 
const HISTORY_LOOKBACK_BLOCKS = 300; 

// Parse targets
const rawTargets = (process.env.TARGETS || "").split(",");
const TARGET_SEQUENCERS = new Set(
    rawTargets.map(a => a.trim().toLowerCase()).filter(a => a)
);

const ROLLUP_ADDRESS = "0x603bb2c05D474794ea97805e8De69bCcFb3bCA12";
const ROLLUP_ADDRESS_LC = ROLLUP_ADDRESS.toLowerCase();

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

// Multicall (propose is sometimes wrapped)
const MULTICALL_ABI = [
    "function aggregate3(tuple(address target, bool allowFailure, bytes callData)[] calls) payable returns (tuple(bool success, bytes returnData)[] returnData)",
    "function aggregate3Value(tuple(address target, bool allowFailure, uint256 value, bytes callData)[] calls) payable returns (tuple(bool success, bytes returnData)[] returnData)"
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

function decodeProposeFromTx(tx, rollupIface, multicallIface) {
    // 1) Direct call to rollup.propose
    try {
        const decoded = rollupIface.parseTransaction({ data: tx.data, value: tx.value });
        if (decoded && decoded.name === "propose") {
            return decoded;
        }
    } catch (_) {}

    // 2) Multicall wrappers (aggregate3 / aggregate3Value)
    try {
        const multi = multicallIface.parseTransaction({ data: tx.data, value: tx.value });
        if (!multi || (multi.name !== "aggregate3" && multi.name !== "aggregate3Value")) return null;

        for (const call of multi.args[0]) {
            // tuple layout differs slightly between aggregate3 and aggregate3Value
            const target = (call.target || call[0] || "").toLowerCase();
            if (target !== ROLLUP_ADDRESS_LC) continue;

            const innerData = call.callData || call[3] || call[2];
            if (!innerData) continue;

            try {
                const decodedInner = rollupIface.parseTransaction({ data: innerData });
                if (decodedInner && decodedInner.name === "propose") {
                    return decodedInner;
                }
            } catch (_) { continue; }
        }
    } catch (_) {}

    return null;
}

function checkAttestation(signatureIndicesBytes, index) {
    const byteIndex = Math.floor(index / 8);
    const shift = 7 - (index % 8);
    const bytesBuffer = ethers.getBytes(signatureIndicesBytes);
    
    if (byteIndex >= bytesBuffer.length) return false;
    
    // Check if bit is set (bit 0 is MSB or LSB? Solidity bitmap usually: index 0 is 7th bit of byte 0)
    // Solidity: (uint8(bytes[byteIndex]) >> shift) & 1
    // shift = 7 - (index % 8)
    return ((bytesBuffer[byteIndex] >> shift) & 1) === 1;
}

// --- Main Class ---

class Aztecanary {
    constructor() {
        this.provider = new ethers.JsonRpcProvider(RPC_URL);
        this.rollup = new ethers.Contract(ROLLUP_ADDRESS, ROLLUP_ABI, this.provider);
        this.iface = new ethers.Interface(ROLLUP_ABI);
        this.mcIface = new ethers.Interface(MULTICALL_ABI);
        
        this.config = {};
        this.processedEpochs = new Set();
        this.epochCache = new Map(); 
        this.checkedL2Blocks = new Set();
        this.nextDuty = { slot: null };
    }

    async init() {
        log("INFO", "Initializing...");
        
        // Log tracked addresses to confirm config
        log("CONFIG", `Tracking ${TARGET_SEQUENCERS.size} validators`, { 
            targets: Array.from(TARGET_SEQUENCERS).map(a => `${a.slice(0,6)}...${a.slice(-4)}`) 
        });

        const [epochDuration, slotDuration, genesisTime, lag] = await Promise.all([
            this.rollup.getEpochDuration(),
            this.rollup.getSlotDuration(),
            this.rollup.getGenesisTime(),
            this.rollup.getLagInEpochs()
        ]);

        this.config = { epochDuration, slotDuration, genesisTime, lag };
        log("CONFIG", "Chain Params", { 
            epochDur: epochDuration.toString(), slotDur: slotDuration.toString(), lag: lag.toString() 
        });

        await this.checkValidatorStatus();
        
        const block = await this.provider.getBlock("latest");
        
        // 1. Audit History
        await this.auditCurrentEpochHistory(block);

        // 2. Realtime (catch up)
        await this.handleBlock(block, false);
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
            
            if (this.epochCache.size > 20) {
                const keys = Array.from(this.epochCache.keys()).sort((a,b) => (a < b ? -1 : 1));
                this.epochCache.delete(keys[0]);
            }
            return data;
        } catch (e) { return null; }
    }

    // --- Core Logic: Check a single block proposal ---
    async checkBlockPerf(l2BlockNum, txHash, context) {
        if (this.checkedL2Blocks.has(l2BlockNum)) return;
        this.checkedL2Blocks.add(l2BlockNum);

        try {
            const tx = await this.provider.getTransaction(txHash);
            if (!tx) return;

            const decoded = decodeProposeFromTx(tx, this.iface, this.mcIface);
            if (!decoded) {
                log("DEBUG", `[${context}] Tx ${txHash} is not a rollup.propose call (or failed to decode)`);
                return;
            }

            const args = decoded.args;
            const callArgs = args._args || args[0];
            if (!callArgs || !callArgs.header) {
                log("ERROR", `[${context}] Missing header data in decoded propose`, { tx: txHash });
                return;
            }

            const header = callArgs.header;
            const attestations = args._attestations || args[1];
            if (!attestations || !attestations.signatureIndices) {
                log("ERROR", `[${context}] Missing attestation payload in propose tx`, { tx: txHash });
                return;
            }

            const slot = BigInt(header.slotNumber.toString());
            const actualProposer = tx.from.toLowerCase();
            const sigBytes = ethers.getBytes(attestations.signatureIndices);

            // Stats for this block
            let stats = { proposer: "N/A", attests: 0, targetAttests: 0 };

            // --- 1. Proposer Check ---
            const epoch = slot / this.config.epochDuration;
            const epochData = await this.ensureEpochData(epoch);
            
            if (epochData) {
                const committeeSize = BigInt(epochData.committee.length);
                const expectedIndex = computeProposerIndex(epoch, slot, epochData.seed, committeeSize);
                const expectedProposer = epochData.committee[Number(expectedIndex)];
                stats.proposer = expectedProposer;

                if (TARGET_SEQUENCERS.has(expectedProposer)) {
                    if (expectedProposer === actualProposer) {
                        log("PERF_SUCCESS", `[${context}] Block ${l2BlockNum} proposed by target ${expectedProposer}`);
                    } else {
                        log("PERF_MISS", `[${context}] Block ${l2BlockNum} (Slot ${slot}) MISSED. Taken by ${actualProposer}`);
                    }
                }
            }

            // --- 2. Attestation Check (current block committee) ---
            if (epochData) {
                const targetsInCommittee = epochData.committee.filter(v => TARGET_SEQUENCERS.has(v));
                // log("ATTEST_DEBUG", `[${context}] Committee info`, { 
                //     l2Block: l2BlockNum.toString(),
                //     epoch: epoch.toString(),
                //     committeeSize: epochData.committee.length,
                //     sigBytes: sigBytes.length,
                //     targetsInCommittee: targetsInCommittee.length
                // });

                let checkedTargets = 0;
                epochData.committee.forEach((validator, index) => {
                    if (TARGET_SEQUENCERS.has(validator)) {
                        checkedTargets++;
                        const didAttest = checkAttestation(attestations.signatureIndices, index);
                        if (!didAttest) {
                            log("ATTEST_MISS", `[${context}] Target ${validator} missed attestation for Block ${l2BlockNum}`);
                        } else {
                            stats.targetAttests++;
                            log("ATTEST_OK", `[${context}] Target ${validator} attested to Block ${l2BlockNum}`);
                        }
                    }
                });
                
                if (checkedTargets > 0) {
                //    log("DEBUG", `Checked ${checkedTargets} targets for attestations in Block ${l2BlockNum}`);
                }
            } else {
                log("DEBUG", `[${context}] Missing epoch data for attestation check`, { epoch: epoch.toString(), l2Block: l2BlockNum.toString() });
            }
            
            log("PERF_CHECK", `Analyzed Block ${l2BlockNum}`, { context, slot: slot.toString(), targetsAttested: stats.targetAttests });

        } catch (e) {
            log("ERROR", `Perf check failed for L2 Block ${l2BlockNum}`, { error: e.message });
        }
    }

    // --- Historical Analysis ---
    async auditCurrentEpochHistory(currentL1Block) {
        try {
            const ts = BigInt(currentL1Block.timestamp);
            const currentSlot = (ts - this.config.genesisTime) / this.config.slotDuration;
            const currentEpoch = currentSlot / this.config.epochDuration;
            const startSlot = currentEpoch * this.config.epochDuration;

            log("AUDIT", `Scanning Epoch ${currentEpoch} (Slots ${startSlot} to ${currentSlot})`);

            const epochData = await this.ensureEpochData(currentEpoch);
            if (!epochData) return;

            const targetsInCommittee = epochData.committee.filter(val => TARGET_SEQUENCERS.has(val));
            if (targetsInCommittee.length === 0) {
                log("INFO", `No tracked targets in epoch ${currentEpoch}; skipping history scan`);
                return;
            }

            const fromBlock = Math.max(0, currentL1Block.number - HISTORY_LOOKBACK_BLOCKS);
            const filter = {
                address: ROLLUP_ADDRESS,
                fromBlock: fromBlock,
                toBlock: "latest",
                topics: [ ethers.id("L2BlockProposed(uint256,bytes32,bytes32[])") ]
            };

            const logs = await this.provider.getLogs(filter);
            const filledSlots = new Set();

            // 1. Process logs
            for(const l of logs) {
                const parsed = this.rollup.interface.parseLog(l);
                if(!parsed) continue;
                
                const l2BlockNum = parsed.args[0];
                const blockData = await this.rollup.getBlock(l2BlockNum);
                const slot = blockData.slotNumber;
                
                if (slot >= startSlot && slot <= currentSlot) {
                    filledSlots.add(slot.toString());
                    await this.checkBlockPerf(l2BlockNum, l.transactionHash, "HISTORY");
                }
            }

            // 2. Identify Missed Proposals (Empty Slots)
            for (let s = startSlot; s <= currentSlot; s++) {
                const slotKey = s.toString();
                if (filledSlots.has(slotKey)) continue; 

                const pIdx = computeProposerIndex(currentEpoch, s, epochData.seed, BigInt(epochData.committee.length));
                const expectedProposer = epochData.committee[Number(pIdx)];
                
                if (TARGET_SEQUENCERS.has(expectedProposer)) {
                     log("PERF_MISS", `[HISTORY] Target ${expectedProposer} MISSED proposal for Slot ${s} (No block produced)`);
                }
            }
            log("AUDIT", "History check complete");

        } catch (e) {
            log("ERROR", "History verification failed", { error: e.message });
        }
    }

    async handleBlock(block, processEvents = true) {
        const ts = BigInt(block.timestamp);
        const slot = (ts - this.config.genesisTime) / this.config.slotDuration;
        const epoch = slot / this.config.epochDuration;

        if (Number(block.number) % 10 === 0) {
            let nextDutyMsg = "none";
            if (this.nextDuty && this.nextDuty.slot !== null) {
                const dutySlot = this.nextDuty.slot;
                const dutyTs = this.config.genesisTime + (dutySlot * this.config.slotDuration);
                const nowTs = BigInt(block.timestamp);
                const delta = dutyTs > nowTs ? Number(dutyTs - nowTs) : 0;
                nextDutyMsg = `slot ${dutySlot.toString()} in ${delta}s`;
            }
            console.log(`[Heartbeat] L1: ${block.number} | Epoch: ${epoch} | Slot: ${slot} | NextDuty: ${nextDutyMsg}`);
        }

        if (this.currentEpoch && this.currentEpoch !== epoch) {
            this.processedEpochs.delete((epoch + this.config.lag).toString());
        }
        this.currentEpoch = epoch;

        const dutyInfo = await this.predictDuties(epoch, slot);
        this.nextDuty = dutyInfo.nextDuty || { slot: null };

        // If no tracked targets in current committee and not forcing history, skip realtime event processing to save RPC.
        if (!processEvents || (dutyInfo && dutyInfo.currentTargets === 0)) return;

        const logs = await this.provider.getLogs({
            address: ROLLUP_ADDRESS,
            fromBlock: block.number,
            toBlock: block.number,
            topics: [ ethers.id("L2BlockProposed(uint256,bytes32,bytes32[])") ]
        });

        for (const l of logs) {
            const parsed = this.rollup.interface.parseLog(l);
            await this.checkBlockPerf(parsed.args[0], l.transactionHash, "REALTIME");
        }
    }

    async predictDuties(currentEpoch, currentSlot) {
        const maxEpoch = BigInt(currentEpoch) + this.config.lag;
        let currentTargets = 0;
        let nextDuty = { slot: null, epoch: null };

        for (let e = BigInt(currentEpoch); e <= maxEpoch; e++) {
            const epochKey = e.toString();
            if (this.processedEpochs.has(epochKey)) continue;

            const data = await this.ensureEpochData(e);
            if (!data) continue;

            const isCurrent = e === BigInt(currentEpoch);
            const tag = isCurrent ? "CURRENT" : "FUTURE";

            const inCommittee = data.committee.filter(val => TARGET_SEQUENCERS.has(val));
            if (inCommittee.length > 0) {
                log("COMMITTEE", `[${tag}] Epoch ${e}: Targets in committee`, { count: inCommittee.length, validators: inCommittee });
                if (isCurrent) currentTargets = inCommittee.length;
                if (nextDuty.slot === null) {
                    const slotHint = isCurrent ? currentSlot : (e * this.config.epochDuration);
                    nextDuty = { slot: slotHint, epoch: e };
                }
            } else {
                if (isCurrent) log("WARN", `[${tag}] Epoch ${e}: No targets in committee`);
            }

            const startSlot = e * this.config.epochDuration;
            for (let i = 0n; i < this.config.epochDuration; i++) {
                const slot = startSlot + i;
                if (isCurrent && slot < currentSlot) continue; 

                const proposerIndex = computeProposerIndex(e, slot, data.seed, BigInt(data.committee.length));
                const proposer = data.committee[Number(proposerIndex)];

                if (TARGET_SEQUENCERS.has(proposer)) {
                    if (nextDuty.slot === null && (!isCurrent || slot >= currentSlot)) {
                        nextDuty = { slot, epoch: e };
                    }
                    const ts = this.config.genesisTime + (slot * this.config.slotDuration);
                    log("DUTY", `[${tag}] Proposer Duty`, {
                        epoch: e.toString(), slot: slot.toString(), validator: proposer,
                        time: new Date(Number(ts) * 1000).toLocaleString()
                    });
                }
            }
            this.processedEpochs.add(epochKey);
        }
        return { currentTargets, nextDuty };
    }

    async start() {
        await this.init();
        this.provider.on("block", async (bn) => {
            if (bn % HEALTH_CHECK_INTERVAL_BLOCKS === 0) await this.checkValidatorStatus();
            const block = await this.provider.getBlock(bn);
            await this.handleBlock(block, true);
        });
        log("INFO", `Monitoring active for ${TARGET_SEQUENCERS.size} targets`);
    }
}

if (TARGET_SEQUENCERS.size === 0) { console.error("Error: Set TARGETS env var"); process.exit(1); }
new Aztecanary().start().catch(console.error);
