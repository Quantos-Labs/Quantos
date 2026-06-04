// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title PQCSignatureRegistry
/// @notice On-chain registry for hybrid PQC + ECDSA signatures.
/// @dev Any L1 chain can deploy this contract to enable "PQC-ready" transactions
/// without modifying its consensus. Users register a PQC public key (Falcon-512
/// or Dilithium-3). Every transaction must include both an ECDSA signature (for
/// native chain acceptance) and a PQC signature (for post-quantum proof). The
/// contract verifies ECDSA on-chain and emits the PQC payload so that Quantos
/// validators or a trusted verifier can confirm the PQC signature off-chain.
/// Once both signatures are confirmed, the action hash is marked as PQC-secured.
///
/// v1.1 improvements:
///  - Domain separation: Falcon digest includes chainId + contract address (anti cross-chain replay)
///  - Key rotation: rotatePqcKey() with grace period — old key stays valid for ROTATION_GRACE_BLOCKS
///  - Batch STARK confirmation: confirmBatchStark() lets L0 verifiers confirm N actions at once
///    via a single 32-byte STARK commitment, drastically reducing on-chain gas costs
contract PQCSignatureRegistry is Ownable2Step {
    /// @notice Supported post-quantum signature algorithms
    enum PqcAlgo { Falcon512, Dilithium3 }

    /// @notice Number of blocks during which both old and new key are valid after rotation
    uint64 public constant ROTATION_GRACE_BLOCKS = 50_400; // ~7 days at 12s/block

    /// @notice Minimum blocks between commit and reveal for PQC key registration.
    /// Creates a ~20-minute observation window: if an attacker with a stolen ECDSA
    /// key commits a malicious Falcon key, the legitimate user sees it on-chain
    /// BEFORE it is finalized and can abort / trigger guardian recovery.
    uint64 public constant MIGRATION_DELAY = 100; // ~20 min at 12s/block

    /// @notice EIP-712-style domain separator for cross-chain replay protection.
    /// Falcon signs: keccak256(DOMAIN_TYPEHASH || chainId || address(this) || payloadHash || nonce)
    bytes32 public immutable DOMAIN_SEPARATOR;

    /// @notice A registered PQC identity for an EVM address
    struct PqcIdentity {
        bytes publicKey;
        PqcAlgo algo;
        uint64 registeredAt;
        bool active;
        /// @dev Pending rotation: new key waiting to take over after grace period
        bytes pendingPublicKey;
        uint64 rotationActivatesAt; // block number when pendingPublicKey becomes canonical
    }

    /// @notice A hybrid-signed action awaiting PQC verification
    struct PendingAction {
        address actor;
        bytes32 payloadHash;
        bytes pqcSignature;
        PqcAlgo algo;
        uint64 submittedAt;
        bool ecdsaVerified;
        bool pqcVerified;
    }

    /// @notice Emitted when an address registers a PQC public key
    event PqcKeyRegistered(address indexed account, PqcAlgo algo, bytes publicKey);
    /// @notice Emitted when a PQC key rotation is initiated
    event PqcKeyRotationInitiated(address indexed account, uint64 activatesAt);
    /// @notice Emitted when a PQC key rotation is finalized
    event PqcKeyRotated(address indexed account);
    /// @notice Emitted when a PQC key is revoked
    event PqcKeyRevoked(address indexed account);
    /// @notice Emitted when a hybrid action is submitted (ECDSA verified on-chain)
    event HybridActionSubmitted(
        bytes32 indexed actionHash,
        address indexed actor,
        bytes32 payloadHash,
        PqcAlgo algo
    );
    /// @notice Emitted when a Quantos verifier confirms the PQC signature off-chain
    event PqcSignatureVerified(bytes32 indexed actionHash, address indexed verifier);
    /// @notice Emitted when an action is fully PQC-secured (both sigs confirmed)
    event ActionPqcSecured(bytes32 indexed actionHash, address indexed actor);
    /// @notice Emitted when a batch of actions is PQC-secured via a single STARK commitment
    event BatchStarkConfirmed(bytes32 indexed starkCommitment, uint256 count, address indexed verifier);

    /// @notice Mapping of EVM address to its PQC identity
    mapping(address => PqcIdentity) public identities;
    /// @notice Mapping of action hash to pending action record
    mapping(bytes32 => PendingAction) public pendingActions;
    /// @notice Mapping of action hash to whether it is fully PQC-secured
    mapping(bytes32 => bool) public pqcSecured;
    /// @notice Trusted verifiers (Quantos L0 validators or designated oracles)
    mapping(address => bool) public trustedVerifiers;
    /// @notice Optimistic challenge window in seconds for PQC verification
    uint256 public challengeWindowSeconds = 300;
    /// @notice Nonce tracking per account to prevent replay
    mapping(address => uint256) public nonces;
    /// @notice STARK commitments already used (prevent replay of batch proofs)
    mapping(bytes32 => bool) public usedStarkCommitments;

    /// @notice Pending commit-reveal commitments: account => keccak256(publicKey || salt)
    mapping(address => bytes32) public pendingCommitments;
    /// @notice Block number at which each pending commitment was submitted
    mapping(address => uint64) public commitmentBlock;
    /// @notice Minimum ETH bond a challenger must post (default 0.01 ETH)
    uint256 public challengeBond = 0.01 ether;
    /// @notice Active challenges: actionHash => challenger address
    mapping(bytes32 => address) public challengers;
    /// @notice Bond amounts locked per actionHash
    mapping(bytes32 => uint256) public challengeBonds;
    /// @notice Whether a verifier has been slashed for a given action
    mapping(bytes32 => bool) public slashed;
    /// @notice Accumulated slash proceeds withdrawable by owner
    uint256 public slashProceeds;

    /// @notice Emitted when a commit-reveal commitment is lodged
    event PqcKeyCommitted(address indexed account, uint64 availableAt);
    /// @notice Emitted when a pending commitment is cancelled by the account owner
    event PqcKeyCommitmentCancelled(address indexed account);

    event ChallengeOpened(bytes32 indexed actionHash, address indexed challenger, uint256 bond);
    event ChallengeRejected(bytes32 indexed actionHash, address indexed challenger);
    event VerifierSlashed(bytes32 indexed actionHash, address indexed challenger, uint256 bond);

    error NoPqcIdentity();
    error IdentityAlreadyExists();
    error InvalidSignatureLength();
    error ActionAlreadySubmitted();
    error ActionNotFound();
    error NotTrustedVerifier();
    error PqcAlreadyVerified();
    error EcdsaVerificationFailed();
    error ChallengeWindowActive();
    error ZeroAddress();
    error RotationNotReady();
    error StarkCommitmentAlreadyUsed();
    error EmptyBatch();
    error InsufficientBond();
    error ChallengeAlreadyExists();
    error ChallengeNotFound();
    error ChallengeWindowExpired();
    error BondTransferFailed();
    error AlreadySlashed();
    error CommitmentRequired();
    error CommitmentMismatch();
    error CommitmentDelayNotElapsed(uint64 availableAt);
    error CommitmentNotFound();
    error CommitmentAlreadyPending();

    constructor(address initialOwner) Ownable(initialOwner) {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("QuantosPQC(uint256 chainId,address registry)"),
            block.chainid,
            address(this)
        ));
    }

    // ── Identity Management ───────────────────────────────────────────────

    /// @notice Step 1 of commit-reveal: lodge a blinded commitment to a Falcon/Dilithium key.
    /// @dev Commitment = keccak256(abi.encodePacked(publicKey, salt)).
    /// After MIGRATION_DELAY blocks (~20 min), call registerPqcKey() to reveal.
    /// If an attacker with a stolen ECDSA key commits a malicious key, the
    /// legitimate owner sees it on-chain BEFORE finalization and can cancel.
    /// @param commitment keccak256(abi.encodePacked(publicKey, salt))
    function commitPqcKey(bytes32 commitment) external {
        if (identities[msg.sender].active) revert IdentityAlreadyExists();
        if (pendingCommitments[msg.sender] != bytes32(0)) revert CommitmentAlreadyPending();

        pendingCommitments[msg.sender] = commitment;
        commitmentBlock[msg.sender] = uint64(block.number);

        uint64 availableAt = uint64(block.number) + MIGRATION_DELAY;
        emit PqcKeyCommitted(msg.sender, availableAt);
    }

    /// @notice Cancel a pending commitment (e.g. if you detect an attacker committed).
    /// Only callable by the account itself.
    function cancelCommitment() external {
        if (pendingCommitments[msg.sender] == bytes32(0)) revert CommitmentNotFound();
        delete pendingCommitments[msg.sender];
        delete commitmentBlock[msg.sender];
        emit PqcKeyCommitmentCancelled(msg.sender);
    }

    /// @notice Step 2 of commit-reveal: register a PQC public key after MIGRATION_DELAY blocks.
    /// @param publicKey The raw PQC public key bytes (Falcon-512 or Dilithium-3)
    /// @param algo Which PQC algorithm this key uses
    /// @param salt Random bytes32 used when hashing the commitment — must match what was committed
    function registerPqcKey(bytes calldata publicKey, PqcAlgo algo, bytes32 salt) external {
        if (publicKey.length == 0) revert InvalidSignatureLength();
        if (identities[msg.sender].active) revert IdentityAlreadyExists();

        // ── Verify commitment ──
        bytes32 expected = pendingCommitments[msg.sender];
        if (expected == bytes32(0)) revert CommitmentRequired();
        if (keccak256(abi.encodePacked(publicKey, salt)) != expected) revert CommitmentMismatch();

        uint64 available = commitmentBlock[msg.sender] + MIGRATION_DELAY;
        if (block.number < available) revert CommitmentDelayNotElapsed(available);

        // ── Clear commitment ──
        delete pendingCommitments[msg.sender];
        delete commitmentBlock[msg.sender];

        identities[msg.sender] = PqcIdentity({
            publicKey: publicKey,
            algo: algo,
            registeredAt: uint64(block.timestamp),
            active: true,
            pendingPublicKey: "",
            rotationActivatesAt: 0
        });

        emit PqcKeyRegistered(msg.sender, algo, publicKey);
    }

    /// @notice Initiate a PQC key rotation. The new key becomes canonical after
    /// ROTATION_GRACE_BLOCKS blocks — during which both old and new key are valid.
    /// This allows relayers/apps time to update their cached public keys.
    /// @param newPublicKey The new Falcon-512 or Dilithium-3 public key bytes
    function rotatePqcKey(bytes calldata newPublicKey) external {
        PqcIdentity storage id = identities[msg.sender];
        if (!id.active) revert NoPqcIdentity();
        if (newPublicKey.length == 0) revert InvalidSignatureLength();

        id.pendingPublicKey = newPublicKey;
        id.rotationActivatesAt = uint64(block.number) + ROTATION_GRACE_BLOCKS;

        emit PqcKeyRotationInitiated(msg.sender, id.rotationActivatesAt);
    }

    /// @notice Finalize the key rotation after the grace period has elapsed.
    /// Anyone can call this once the grace period is over.
    function finalizeRotation(address account) external {
        PqcIdentity storage id = identities[account];
        if (!id.active) revert NoPqcIdentity();
        if (id.rotationActivatesAt == 0 || block.number < id.rotationActivatesAt) revert RotationNotReady();

        id.publicKey = id.pendingPublicKey;
        id.pendingPublicKey = "";
        id.rotationActivatesAt = 0;

        emit PqcKeyRotated(account);
    }

    /// @notice Returns the currently effective public key for an account.
    /// During a rotation grace period, returns the OLD key (still canonical).
    function effectivePublicKey(address account) external view returns (bytes memory) {
        return identities[account].publicKey;
    }

    /// @notice Revoke the caller's PQC identity.
    function revokePqcKey() external {
        if (!identities[msg.sender].active) revert NoPqcIdentity();
        delete identities[msg.sender];
        emit PqcKeyRevoked(msg.sender);
    }

    // ── Trusted Verifiers ───────────────────────────────────────────────

    /// @notice Add a trusted verifier. Only owner.
    function addVerifier(address verifier) external onlyOwner {
        if (verifier == address(0)) revert ZeroAddress();
        trustedVerifiers[verifier] = true;
    }

    /// @notice Remove a trusted verifier. Only owner.
    function removeVerifier(address verifier) external onlyOwner {
        trustedVerifiers[verifier] = false;
    }

    /// @notice Update the optimistic challenge window. Only owner.
    function setChallengeWindow(uint256 seconds_) external onlyOwner {
        challengeWindowSeconds = seconds_;
    }

    /// @notice Update the minimum challenge bond. Only owner.
    function setChallengeBond(uint256 bond) external onlyOwner {
        challengeBond = bond;
    }

    /// @notice Owner withdraws accumulated slash proceeds.
    function withdrawSlashProceeds() external onlyOwner {
        uint256 amount = slashProceeds;
        slashProceeds = 0;
        (bool ok,) = payable(owner()).call{value: amount}("");
        if (!ok) revert BondTransferFailed();
    }

    // ── Hybrid Action Submission ────────────────────────────────────────

    /// @notice Compute the domain-separated digest that the Falcon key must sign.
    /// Includes DOMAIN_SEPARATOR (chainId + registry address) to prevent cross-chain replay.
    /// @param actor The EVM address submitting the action
    /// @param payloadHash The keccak256 of the action payload
    /// @param nonce The current account nonce
    function falconDigest(address actor, bytes32 payloadHash, uint256 nonce)
        public view returns (bytes32)
    {
        return keccak256(abi.encode(DOMAIN_SEPARATOR, actor, payloadHash, nonce));
    }

    /// @notice Submit an action with both ECDSA and PQC signatures.
    /// @dev The caller must have registered a PQC key. ECDSA is verified
    /// on-chain against the recovered signer. The PQC signature is stored
    /// and emitted for off-chain verification by a trusted verifier.
    /// The Falcon/Dilithium signature must be over falconDigest(msg.sender, payloadHash, nonce)
    /// to prevent cross-chain replay attacks.
    /// @param payloadHash Hash of the action payload (tx data, intent, etc.)
    /// @param pqcSignature The PQC signature over falconDigest(actor, payloadHash, nonce)
    /// @param v ECDSA v value
    /// @param r ECDSA r value
    /// @param s ECDSA s value
    /// @return actionHash The unique hash identifying this hybrid action
    function submitHybridAction(
        bytes32 payloadHash,
        bytes calldata pqcSignature,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bytes32 actionHash) {
        PqcIdentity storage id = identities[msg.sender];
        if (!id.active) revert NoPqcIdentity();
        if (pqcSignature.length == 0) revert InvalidSignatureLength();

        // Verify ECDSA signature on payloadHash (standard eth_sign format)
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
        address recovered = ecrecover(ethHash, v, r, s);
        if (recovered != msg.sender) revert EcdsaVerificationFailed();

        // Unique action hash = keccak(actor, payloadHash, nonce)
        uint256 nonce = nonces[msg.sender]++;
        actionHash = keccak256(abi.encodePacked(msg.sender, payloadHash, nonce));

        if (pendingActions[actionHash].submittedAt != 0) revert ActionAlreadySubmitted();

        pendingActions[actionHash] = PendingAction({
            actor: msg.sender,
            payloadHash: payloadHash,
            pqcSignature: pqcSignature,
            algo: id.algo,
            submittedAt: uint64(block.timestamp),
            ecdsaVerified: true,
            pqcVerified: false
        });

        emit HybridActionSubmitted(actionHash, msg.sender, payloadHash, id.algo);
        return actionHash;
    }

    /// @notice A trusted verifier confirms that the PQC signature for a single action
    /// is valid off-chain (e.g., via Falcon-512 or Dilithium-3 verification).
    /// @param actionHash The hybrid action to verify
    function verifyPqcSignature(bytes32 actionHash) external {
        if (!trustedVerifiers[msg.sender]) revert NotTrustedVerifier();

        PendingAction storage action = pendingActions[actionHash];
        if (action.submittedAt == 0) revert ActionNotFound();
        if (action.pqcVerified) revert PqcAlreadyVerified();

        action.pqcVerified = true;
        pqcSecured[actionHash] = true;

        emit PqcSignatureVerified(actionHash, msg.sender);
        emit ActionPqcSecured(actionHash, action.actor);
    }

    /// @notice Batch-confirm N actions via a single 32-byte STARK commitment.
    /// @dev A trusted L0 verifier submits a STARK proof commitment that aggregates
    /// the Falcon/Dilithium verification of all actionHashes off-chain.
    /// Gas cost: ~21k + N*5k instead of N*50k for individual verifyPqcSignature calls.
    /// The starkCommitment is the SHA3-256 hash of the Winterfell STARK proof bytes,
    /// as produced by the Quantos L0 stark_prover::prove_batch().
    /// @param actionHashes The list of action hashes covered by the STARK proof
    /// @param starkCommitment 32-byte commitment of the STARK batch proof
    function confirmBatchStark(
        bytes32[] calldata actionHashes,
        bytes32 starkCommitment
    ) external {
        if (!trustedVerifiers[msg.sender]) revert NotTrustedVerifier();
        if (actionHashes.length == 0) revert EmptyBatch();
        if (usedStarkCommitments[starkCommitment]) revert StarkCommitmentAlreadyUsed();

        usedStarkCommitments[starkCommitment] = true;

        uint256 confirmed = 0;
        for (uint256 i = 0; i < actionHashes.length; i++) {
            bytes32 h = actionHashes[i];
            PendingAction storage action = pendingActions[h];
            if (action.submittedAt == 0 || action.pqcVerified) continue;

            action.pqcVerified = true;
            pqcSecured[h] = true;
            confirmed++;

            emit PqcSignatureVerified(h, msg.sender);
            emit ActionPqcSecured(h, action.actor);
        }

        emit BatchStarkConfirmed(starkCommitment, confirmed, msg.sender);
    }

    // ── Optimistic Challenge ────────────────────────────────────────────

    /// @notice Open a challenge against a PQC verification by posting a bond.
    /// @dev Must be called within the challenge window (before submittedAt + challengeWindowSeconds).
    /// The challenger asserts the verifier's Falcon/Dilithium attestation was fraudulent.
    /// The owner (or a governance contract) reviews the off-chain proof and calls
    /// slashVerifier() if the challenge is valid, or rejectChallenge() otherwise.
    /// Bond is refunded if the challenge succeeds (slash), burned to owner if rejected.
    function challengePqcVerification(bytes32 actionHash) external payable {
        if (msg.value < challengeBond) revert InsufficientBond();
        if (challengers[actionHash] != address(0)) revert ChallengeAlreadyExists();
        if (slashed[actionHash]) revert AlreadySlashed();

        PendingAction storage action = pendingActions[actionHash];
        if (action.submittedAt == 0) revert ActionNotFound();

        uint256 challengeDeadline = action.submittedAt + challengeWindowSeconds;
        if (block.timestamp > challengeDeadline) revert ChallengeWindowExpired();

        challengers[actionHash] = msg.sender;
        challengeBonds[actionHash] = msg.value;

        // Revert pqcVerified status while challenge is pending
        if (action.pqcVerified) {
            action.pqcVerified = false;
            pqcSecured[actionHash] = false;
        }

        emit ChallengeOpened(actionHash, msg.sender, msg.value);
    }

    /// @notice Owner resolves a challenge as valid: the verifier attested a bad PQC sig.
    /// The challenger receives their bond back. The action remains un-secured.
    /// @dev In a future version, verifier stake could be slashed here via a staking contract.
    function slashVerifier(bytes32 actionHash) external onlyOwner {
        address challenger = challengers[actionHash];
        if (challenger == address(0)) revert ChallengeNotFound();
        if (slashed[actionHash]) revert AlreadySlashed();

        uint256 bond = challengeBonds[actionHash];
        slashed[actionHash] = true;
        challengers[actionHash] = address(0);
        challengeBonds[actionHash] = 0;

        // Refund the challenger's bond — they were right
        (bool ok,) = payable(challenger).call{value: bond}("");
        if (!ok) revert BondTransferFailed();

        emit VerifierSlashed(actionHash, challenger, bond);
    }

    /// @notice Owner rejects a challenge: the verifier's attestation was correct.
    /// The challenger's bond is transferred to the contract owner as a penalty.
    /// The action is re-marked as pqcSecured.
    function rejectChallenge(bytes32 actionHash) external onlyOwner {
        address challenger = challengers[actionHash];
        if (challenger == address(0)) revert ChallengeNotFound();

        uint256 bond = challengeBonds[actionHash];
        challengers[actionHash] = address(0);
        challengeBonds[actionHash] = 0;

        // Re-secure the action — the challenge was frivolous
        PendingAction storage action = pendingActions[actionHash];
        if (action.submittedAt != 0 && !action.pqcVerified) {
            action.pqcVerified = true;
            pqcSecured[actionHash] = true;
        }

        // Bond goes to owner as penalty for frivolous challenge
        slashProceeds += bond;

        emit ChallengeRejected(actionHash, challenger);
    }

    // ── View Functions ──────────────────────────────────────────────────

    /// @notice Check whether an action hash is fully PQC-secured.
    function isPqcSecured(bytes32 actionHash) external view returns (bool) {
        return pqcSecured[actionHash];
    }

    /// @notice Get the pending action details.
    function getPendingAction(bytes32 actionHash) external view returns (PendingAction memory) {
        return pendingActions[actionHash];
    }

    /// @notice Get the PQC identity of an account.
    function getPqcIdentity(address account) external view returns (PqcIdentity memory) {
        return identities[account];
    }

    /// @notice Check if an account has an active PQC identity.
    function hasPqcIdentity(address account) external view returns (bool) {
        return identities[account].active;
    }
}
