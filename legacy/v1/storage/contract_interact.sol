# Submit proof metadata hash to smart contract
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// OpenZeppelin Imports using direct GitHub URLs
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.9.0/contracts/access/Ownable.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.9.0/contracts/security/ReentrancyGuard.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.9.0/contracts/utils/Counters.sol";

// STEP 1: Define the IVerifier interface
// This signature is PRECISELY derived from your proof.json and verification_key.json screenshots.
// - pi_a: uint[3] because proof.json shows 3 elements (e.g., "1600...", "836...", "1")
// - pi_b: uint[2][2] as it's a 2x2 array in proof.json
// - pi_c: uint[3] because proof.json shows 3 elements (e.g., "252...", "479...", "0")
// - input: uint[1] because verification_key.json shows "nPublic": 1
interface IVerifier {
    function verifyProof(
        uint[2] calldata pi_a,
        uint[2][2] calldata pi_b,
        uint[2] calldata pi_c,
        uint[1] calldata input
    ) external view returns (bool r);
}

/**
 * @title ZKThreatDetectionSystem
 * @dev A comprehensive smart contract for verifying and managing ZK proofs of threat detections.
 * @notice This contract allows for the submission of threat reports, verification of associated
 * ZK proofs, and management of reporter reputation, compatible with Remix IDE.
 */
contract ZKThreatDetectionSystem is Ownable, ReentrancyGuard {
    using Counters for Counters.Counter;

    // --- State Variables ---

    Counters.Counter private _reportIdCounter; // Counter for unique threat report IDs

    // STEP 2a: Add a state variable to hold the Verifier contract instance
    IVerifier public i_verifier; // Using 'i_' prefix for interface instance

    // Mapping from report ID to ThreatReport struct
    mapping(uint256 => ThreatReport) public threatReports;
    // Mapping to track used proof hashes to prevent reuse
    mapping(bytes32 => bool) public usedProofHashes;
    // Mapping from ZK nullifier hash to ZKIdentity struct
    mapping(bytes32 => ZKIdentity) public zkIdentities;
    // Mapping from submitter address to their associated ZK nullifier hash
    mapping(address => bytes32) public addressToZKIdentity;

    // --- Enums ---

    /**
     * @dev Defines the possible types of threats that can be reported.
     */
    enum ThreatType {
        PHISHING,
        MALWARE,
        NETWORK_ANOMALY,
        SUSPICIOUS_FILE,
        DATA_BREACH,
        OTHER
    }

    /**
     * @dev Defines the severity levels for reported threats.
     */
    enum ThreatSeverity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    // --- Structs ---

    /**
     * @dev Represents a single threat report submitted to the system.
     * @param id Unique identifier for the report.
     * @param proofHash Hash of the ZK proof submitted.
     * @param metadataHash Hash of the threat metadata.
     * @param ipfsHash IPFS CID where detailed metadata is stored.
     * @param submitter Address of the entity submitting the report.
     * @param timestamp Block timestamp when the report was submitted.
     * @param threatType Categorization of the detected threat.
     * @param severity Severity level of the threat.
     * @param verified Status indicating if the ZK proof has been successfully verified.
     * @param reputation Reputation score of the submitter at the time of submission.
     */
    struct ThreatReport {
        uint256 id;
        bytes32 proofHash;
        bytes32 metadataHash;
        string ipfsHash;
        address submitter;
        uint256 timestamp;
        ThreatType threatType;
        ThreatSeverity severity;
        bool verified;
        uint256 reputation;
    }

    /**
     * @dev Represents a ZK identity within the system, used for reputation tracking.
     * @param nullifierHash Semaphore nullifier hash, serving as the unique identifier for the ZK identity.
     * @param reputation Accumulated reputation score for this identity.
     * @param totalReports Total number of reports submitted by this identity.
     * @param verifiedReports Number of reports from this identity that have been verified.
     * @param isActive Boolean indicating if the identity has been initialized/is active.
     */
    struct ZKIdentity {
        bytes32 nullifierHash;
        uint256 reputation;
        uint256 totalReports;
        uint256 verifiedReports;
        bool isActive;
    }

    // --- Events ---

    /**
     * @dev Emitted when a new threat report is successfully submitted.
     * @param reportId The unique ID of the submitted report.
     * @param proofHash The hash of the ZK proof.
     * @param submitter The address of the report submitter.
     * @param threatType The type of threat reported.
     * @param severity The severity of the reported threat.
     */
    event ThreatReportSubmitted(
        uint256 indexed reportId,
        bytes32 indexed proofHash,
        address indexed submitter,
        ThreatType threatType,
        ThreatSeverity severity
    );

    /**
     * @dev Emitted after a ZK proof verification attempt.
     * @param reportId The ID of the report whose proof was verified.
     * @param proofHash The hash of the ZK proof.
     * @param verified True if the proof was successfully verified, false otherwise.
     */
    event ProofVerified(
        uint256 indexed reportId,
        bytes32 indexed proofHash,
        bool verified
    );

    /**
     * @dev Emitted when a ZK identity's reputation is updated.
     * @param zkIdentity The nullifier hash representing the ZK identity.
     * @param newReputation The updated reputation score for the identity.
     */
    event ReputationUpdated(
        bytes32 indexed zkIdentity,
        uint256 newReputation
    );

    /**
     * @dev Emitted when IPFS metadata for a report is stored or updated.
     * @param reportId The ID of the report.
     * @param ipfsHash The IPFS CID where metadata is stored.
     */
    event MetadataStored(
        uint256 indexed reportId,
        string ipfsHash
    );

    // --- Custom Errors ---

    // Using custom errors for gas efficiency and clearer error messages
    error InvalidProofHash();
    error ProofHashAlreadyUsed();
    error ReportDoesNotExist();
    error ReportAlreadyVerified();
    error InvalidLimit();
    error OffsetOutOfBounds();

    // --- Modifiers ---

    /**
     * @dev Checks if a given proof hash is valid (non-zero) and has not been used before.
     * Reverts with `InvalidProofHash` or `ProofHashAlreadyUsed` if conditions are not met.
     * @param _proofHash The proof hash to validate.
     */
    modifier onlyNewValidProofHash(bytes32 _proofHash) {
        if (_proofHash == bytes32(0)) revert InvalidProofHash();
        if (usedProofHashes[_proofHash]) revert ProofHashAlreadyUsed();
        _;
    }

    /**
     * @dev Checks if a report with the given ID exists.
     * Reverts with `ReportDoesNotExist` if the report ID is invalid.
     * @param _reportId The ID of the report to check.
     */
    modifier existingReport(uint256 _reportId) {
        if (_reportId == 0 || _reportId > _reportIdCounter.current()) revert ReportDoesNotExist();
        _;
    }

    // STEP 2b: Modified constructor to accept the Verifier contract address
    /**
     * @dev Constructor for ZKThreatDetectionSystem.
     * The deployer of this contract will automatically be set as the owner by Ownable.
     * @param _verifierAddress The address of the deployed ZKP Verifier smart contract.
     */
    constructor(address _verifierAddress) {
        require(_verifierAddress != address(0), "Verifier address cannot be zero");
        i_verifier = IVerifier(_verifierAddress);
    }

    // --- External Functions ---

    /**
     * @dev Submits a new threat report along with its ZK proof details.
     * This function handles the creation of a new report, assigns a unique ID,
     * and initializes or updates the associated ZK identity's reputation.
     * @param _proofHash The unique hash of the ZK proof.
     * @param _metadataHash The hash of the associated threat metadata.
     * @param _ipfsHash The IPFS Content Identifier (CID) pointing to the detailed metadata.
     * @param _threatType The classified type of the threat.
     * @param _severity The assessed severity of the threat.
     * @param _zkNullifier The nullifier hash for the ZK identity. Use `bytes32(0)` if submitting anonymously without a ZK identity.
     */
    function submitThreatReport(
        bytes32 _proofHash,
        bytes32 _metadataHash,
        string memory _ipfsHash,
        ThreatType _threatType,
        ThreatSeverity _severity,
        bytes32 _zkNullifier
    ) external nonReentrant onlyNewValidProofHash(_proofHash) {
        _reportIdCounter.increment();
        uint256 reportId = _reportIdCounter.current();

        uint256 currentReputation = 0;
        if (_zkNullifier != bytes32(0)) {
            currentReputation = _updateZKIdentity(_zkNullifier);
            // Link the submitter's address to the ZK identity for future reference if not already linked
            if (addressToZKIdentity[msg.sender] == bytes32(0)) {
                addressToZKIdentity[msg.sender] = _zkNullifier;
            }
        }

        threatReports[reportId] = ThreatReport({
            id: reportId,
            proofHash: _proofHash,
            metadataHash: _metadataHash,
            ipfsHash: _ipfsHash,
            submitter: msg.sender,
            timestamp: block.timestamp,
            threatType: _threatType,
            severity: _severity,
            verified: false, // Initially false, verified separately
            reputation: currentReputation
        });

        usedProofHashes[_proofHash] = true;

        emit ThreatReportSubmitted(reportId, _proofHash, msg.sender, _threatType, _severity);
        emit MetadataStored(reportId, _ipfsHash);
    }

    // STEP 3a & 3b: Modified verifyZKProof function signature and logic to use IVerifier
    /**
     * @dev Verifies a ZK proof for a given threat report by calling an external Verifier contract.
     * This function can only be called by the contract owner. Upon successful verification,
     * the report's status is updated, and the submitter's reputation is increased.
     *
     * @param _reportId The ID of the threat report to verify.
     * @param _piA The `pi_a` component of the ZK proof (from proof.json).
     * @param _piB The `pi_b` component of the ZK proof (from proof.json).
     * @param _piC The `pi_c` component of the ZK proof (from proof.json).
     * @param _pubSignals The public inputs associated with the ZK proof (from public.json).
     */
    function verifyZKProof(
        uint256 _reportId,
        uint[2] calldata _piA,
        uint[2][2] calldata _piB,
        uint[2] calldata _piC,
        uint[1] calldata _pubSignals
    ) external onlyOwner existingReport(_reportId) nonReentrant {
        ThreatReport storage report = threatReports[_reportId];
        if (report.verified) revert ReportAlreadyVerified();

        // Call the external Verifier contract's verifyProof function
        bool isValid = i_verifier.verifyProof(_piA, _piB, _piC, _pubSignals);

        // STEP 3c: Add a security check: Link public input to the stored report data.
        // This is CRUCIAL. The public input of your ZK proof (e.g., the hash of some data, or a nullifier)
        // must match something already stored in the report to ensure the proof is for THIS report.
        //
        // Based on your public.json showing `["1"]`,
        // if your circuit always outputs `1` as its public input, then this check should be:
        require(_pubSignals[0] == 1, "ZKTD: Public input does not match expected value (e.g., 1)");

        // If, however, your circuit is designed to output a hash (like metadataHash) as its public input,
        // you would use something like:
        // require(bytes32(_pubSignals[0]) == report.metadataHash, "ZKTD: Public input does not match metadata hash");
        // OR if it's a nullifier:
        // require(bytes32(_pubSignals[0]) == addressToZKIdentity[report.submitter], "ZKTD: Public input does not match ZK nullifier");


        report.verified = isValid;

        // If proof is valid and a ZK identity is associated, increase reputation
        bytes32 zkNullifier = addressToZKIdentity[report.submitter];
        if (isValid && zkNullifier != bytes32(0)) {
            _increaseReputation(zkNullifier, _calculateReputationReward(report.severity));
        }

        emit ProofVerified(_reportId, report.proofHash, isValid);
    }

    /**
     * @dev Retrieves the details of a specific threat report.
     * @param _reportId The ID of the report to retrieve.
     * @return ThreatReport A struct containing all details of the requested report.
     */
    function getThreatReport(uint256 _reportId)
        external
        view
        existingReport(_reportId)
        returns (ThreatReport memory)
    {
        return threatReports[_reportId];
    }

    /**
     * @dev Retrieves a paginated list of all verified threat reports.
     * This function iterates through all reports to find verified ones, which can be gas-intensive
     * for a very large number of reports. Consider off-chain indexing for scale.
     * @param _offset The starting index for pagination (0-based).
     * @param _limit The maximum number of reports to return (max 100).
     * @return ThreatReport[] An array of verified threat reports.
     */
    function getVerifiedReports(uint256 _offset, uint256 _limit)
        external
        view
        returns (ThreatReport[] memory)
    {
        if (_limit == 0 || _limit > 100) revert InvalidLimit();

        uint256 totalReports = _reportIdCounter.current();
        uint256 verifiedCount = 0;

        // First pass: Count verified reports to determine array size and validate offset
        for (uint256 i = 1; i <= totalReports; i++) {
            if (threatReports[i].verified) {
                verifiedCount++;
            }
        }

        if (_offset >= verifiedCount) revert OffsetOutOfBounds();

        uint256 resultSize = verifiedCount - _offset;
        if (resultSize > _limit) {
            resultSize = _limit;
        }
        ThreatReport[] memory result = new ThreatReport[](resultSize);

        uint256 currentVerifiedIndex = 0;
        uint256 resultIndex = 0;

        // Second pass: Populate the result array with verified reports based on offset and limit
        for (uint256 i = 1; i <= totalReports && resultIndex < resultSize; i++) {
            if (threatReports[i].verified) {
                if (currentVerifiedIndex >= _offset) {
                    result[resultIndex] = threatReports[i];
                    resultIndex++;
                }
                currentVerifiedIndex++;
            }
        }

        return result;
    }

    /**
     * @dev Retrieves the ZK identity information for a given nullifier hash.
     * @param _nullifierHash The nullifier hash of the ZK identity.
     * @return ZKIdentity A struct containing the details of the ZK identity.
     */
    function getZKIdentity(bytes32 _nullifierHash)
        external
        view
        returns (ZKIdentity memory)
    {
        return zkIdentities[_nullifierHash];
    }

    /**
     * @dev Returns the total number of threat reports submitted to the system.
     * @return uint256 The current count of all threat reports.
     */
    function getTotalReports() external view returns (uint256) {
        return _reportIdCounter.current();
    }

    /**
     * @dev Helper function to test abi.encodePacked and keccak256 for debugging verification.
     * This function allows us to get the exact hash that the contract expects for a given
     * proof and public inputs.
     * @param _p Raw proof bytes.
     * @param _pi Public inputs.
     * @return bytes32 The computed hash.
     */
    function debugComputeProofHash(bytes calldata _p, uint256[] calldata _pi)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(_p, _pi));
    }

    /**
     * @dev Allows the owner to update the IPFS hash for an existing threat report.
     * This is useful if metadata needs to be corrected or updated.
     * @param _reportId The ID of the report to update.
     * @param _newIpfsHash The new IPFS CID for the report's metadata.
     */
    function updateIPFSHash(uint256 _reportId, string memory _newIpfsHash)
        external
        onlyOwner
        existingReport(_reportId)
    {
        threatReports[_reportId].ipfsHash = _newIpfsHash;
        emit MetadataStored(_reportId, _newIpfsHash);
    }

    // --- Internal Functions ---

    /**
     * @dev Updates or initializes a ZK identity's statistics.
     * If the identity is new, it's activated with a base reputation.
     * Increments the total reports count for the identity.
     * @param _nullifierHash The nullifier hash of the ZK identity.
     * @return uint256 The current reputation of the updated identity.
     */
    function _updateZKIdentity(bytes32 _nullifierHash) internal returns (uint256) {
        ZKIdentity storage identity = zkIdentities[_nullifierHash];

        // Initialize new ZK Identity
        if (!identity.isActive) {
            identity.nullifierHash = _nullifierHash;
            identity.reputation = 100; // Base reputation for new identities
            identity.isActive = true;
        }

        identity.totalReports++;
        return identity.reputation;
    }

    /**
     * @dev Increases the reputation of a ZK identity and increments verified reports count.
     * Emits a `ReputationUpdated` event.
     * @param _nullifierHash The nullifier hash of the ZK identity to update.
     * @param _amount The amount to add to the reputation.
     */
    function _increaseReputation(bytes32 _nullifierHash, uint256 _amount) internal {
        ZKIdentity storage identity = zkIdentities[_nullifierHash];
        identity.reputation += _amount;
        identity.verifiedReports++;

        emit ReputationUpdated(_nullifierHash, identity.reputation);
    }

    /**
     * @dev Calculates the reputation reward based on the threat's severity.
     * @param _severity The severity level of the threat.
     * @return uint256 The calculated reputation points to be rewarded.
     */
    function _calculateReputationReward(ThreatSeverity _severity) internal pure returns (uint256) {
        if (_severity == ThreatSeverity.CRITICAL) return 50;
        if (_severity == ThreatSeverity.HIGH) return 30;
        if (_severity == ThreatSeverity.MEDIUM) return 20;
        return 10; // Default for LOW or OTHER
    }

    // STEP 3d: The old _verifyProof function is now removed, as we call the external IVerifier.
    // If you need to keep it for any legacy reason or other internal use, ensure it doesn't conflict.
    // Otherwise, completely remove this function.
}