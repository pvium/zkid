// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IP2IDVault} from "./interfaces/IP2IDVault.sol";
import {IP2IDVerifier} from "./interfaces/IP2IDVerifier.sol";
import {IP2IdVaultFactory} from "./interfaces/IP2IdVaultFactory.sol";

/// @title P2IDVault
/// @notice A namespace-bound vault that holds ERC-20 funds until the identity owner claims them.
/// @dev **A bare ERC-20 transfer to this contract is irrevocable: it records no funder, has no
///      refund path, and is claimable only through the factory's default verifier.** Use fund()
///      when refund rights, a funding constraint, or a specific verifier are required.
///
///      Verifiers. Every deposit names the IP2IDVerifier whose proofs can release it, chosen by
///      the payer from the factory's approved registry (fund() takes the factory default). The
///      vault checks approval when funding and again on every claim, so a verifier found unsafe
///      can be revoked by the factory owner: deposits under it freeze until re-approval and stay
///      refundable. Anyone can therefore build a verifier for Pvium users to claim through,
///      without the vault, its address, or other deposits changing.
///
///      Every claim path hands a verifier this vault's `saltCommitment` plus a proof and gets
///      back the wallet to pay; the verifier reverts unless the proof is for exactly that
///      identity, so a proof for another identity can never claim this vault.
///
///      Accounting is per bucket, where a bucket is (verifier, constraint, token) and the
///      default bucket of a verifier is constraint == bytes32(0). `constraint` is an opaque
///      bytes32 the funder attaches; the verifier decides what satisfies it (e.g. a registered
///      attester's signature over it). Each bucket keeps its own deposit-id list and cursor, so
///      sweeps are bounded per bucket, can be paged (`depositCountLimit` = number of deposit
///      records visited from the cursor, consumed or not; 0 = all) or aimed at specific ids, and
///      spam in other tokens or buckets never blocks a sweep.
///
///      Proof freshness ratchet, per verifier: every proof presented must be at least as fresh
///      as the newest one this vault has seen under that verifier, and a newer proof becomes the
///      owner proof. So the moment the identity's holder presents a proof for a new wallet
///      (refreshProof, or any claim), every older proof under that verifier is dead for this
///      vault. Funds already inside before that reset are not protected: reset immediately
///      after a wallet compromise.
///
///      Invariant kept by every path: token balance >= trackedTotal[token] (the unconsumed
///      deposits of that token). A sweep pays out only what it marks consumed, plus, for the
///      default verifier, the untracked (bare-transfer) surplus, so unswept deposits stay
///      fully refundable.
contract P2IDVault is IP2IDVault {
    /// @notice Deployer (PviumP2IdVaultFactory): verifier registry, and the only caller of initialize() and fundFor().
    address public immutable factory;
    bytes32 public nsHash;
    bytes32 public saltCommitment;
    uint64 public minRefundWindow;
    uint64 public maxRefundWindow;
    bool private _initialized;

    /// @notice Wallet of the newest proof presented under a verifier; paid by that verifier's default-bucket sweeps.
    mapping(address verifier => address) public owner;
    /// @notice Issue time of that proof. Older proofs are refused under that verifier on every path.
    mapping(address verifier => uint64) public latestProofIat;

    /// @notice All deposits ever made, by id.
    Deposit[] public deposits;

    /// @notice Unconsumed total per (verifier, constraint, token) bucket.
    mapping(address verifier => mapping(bytes32 constraint => mapping(address token => uint256)))
        public bucketTotal;
    /// @notice Sum of all unconsumed deposits per token: what the balance must never drop below.
    mapping(address token => uint256) public trackedTotal;
    /// @dev Deposit ids per bucket, in funding order.
    mapping(address verifier => mapping(bytes32 constraint => mapping(address token => uint256[])))
        private _bucketDeposits;
    /// @notice Index into the bucket's deposit list below which every deposit is consumed.
    mapping(address verifier => mapping(bytes32 constraint => mapping(address token => uint256)))
        public bucketCursor;

    uint256 private reentrancyLock = 1;

    error InvalidRefundWindow();
    error VerifierNotApproved(address verifier);
    error InvalidRefundAmount();
    error InvalidToken();
    error OwnerNotInitialized();
    error ProofTooOld();
    error InvalidWallet();
    error NotFunder();
    error DepositConsumed();
    error DepositNotInBucket(uint256 depositId);
    error ConstraintRequired();
    error NotFactory();
    error AlreadyInitialized();
    error RefundNotReady();
    error TokenCallFailed();
    error TokenBalanceQueryFailed();
    error AmountTooLarge();
    error Reentrancy();

    /// @dev No constructor arguments, so the creation code is identical for every vault and
    ///      `keccak256(creationCode)` is a constant anyone can use to derive an identity's vault
    ///      address from the factory address. The deployer is recorded and must call initialize().
    constructor() {
        factory = msg.sender;
    }

    /// @notice Set by the factory once, immediately after deployment.
    function initialize(
        bytes32 _nsHash,
        bytes32 _saltCommitment,
        uint64 _minRefundWindow,
        uint64 _maxRefundWindow
    ) external onlyFactory {
        if (_initialized) revert AlreadyInitialized();
        if (_minRefundWindow > _maxRefundWindow) revert InvalidRefundWindow();
        _initialized = true;
        nsHash = _nsHash;
        saltCommitment = _saltCommitment;
        minRefundWindow = _minRefundWindow;
        maxRefundWindow = _maxRefundWindow;
    }

    // ------------------------------------------------------------------ funding

    /// @notice Fund under the factory's default verifier.
    /// @param constraint Opaque bytes32 the verifier must see satisfied before this deposit can
    ///        be swept (e.g. a screening commitment); bytes32(0) for the default bucket.
    function fund(
        address token,
        uint256 amount,
        bytes32 constraint,
        uint64 refundWindow
    ) external nonReentrant returns (uint256 depositId) {
        return
            _fund(
                msg.sender,
                defaultVerifier(),
                token,
                amount,
                constraint,
                refundWindow
            );
    }

    /// @notice Fund under any verifier the factory has approved.
    function fundWith(
        address verifier,
        address token,
        uint256 amount,
        bytes32 constraint,
        uint64 refundWindow
    ) external nonReentrant returns (uint256 depositId) {
        return
            _fund(
                msg.sender,
                verifier,
                token,
                amount,
                constraint,
                refundWindow
            );
    }

    /// @notice Factory-only: fund on behalf of `funder`, who keeps the refund right. Tokens are
    ///         pulled from the factory, which has already collected them from `funder`.
    function fundFor(
        address funder,
        address verifier,
        address token,
        uint256 amount,
        bytes32 constraint,
        uint64 refundWindow
    ) external nonReentrant onlyFactory returns (uint256 depositId) {
        if (funder == address(0)) revert InvalidWallet();
        return _fund(funder, verifier, token, amount, constraint, refundWindow);
    }

    /// @dev Pull `amount` of `token` from msg.sender and record a deposit owned by `funder`.
    function _fund(
        address funder,
        address verifier,
        address token,
        uint256 amount,
        bytes32 constraint,
        uint64 refundWindow
    ) private onlyApprovedVerifier(verifier) returns (uint256 depositId) {
        if (token.code.length == 0) revert InvalidToken();
        if (refundWindow < minRefundWindow || refundWindow > maxRefundWindow)
            revert InvalidRefundWindow();
        if (amount == 0 || amount > type(uint128).max)
            revert InvalidRefundAmount();

        uint256 beforeBalance = _balanceOf(token);
        _callToken(
            token,
            abi.encodeWithSignature(
                "transferFrom(address,address,uint256)",
                msg.sender,
                address(this),
                amount
            )
        );
        uint256 afterBalance = _balanceOf(token);
        if (afterBalance <= beforeBalance) revert InvalidRefundAmount();
        uint256 credited = afterBalance - beforeBalance;
        if (credited > type(uint128).max) revert AmountTooLarge();

        depositId = deposits.length;
        deposits.push(
            Deposit({
                funder: funder,
                fundedAt: uint64(block.timestamp),
                consumed: false,
                token: token,
                refundWindow: refundWindow,
                verifier: verifier,
                amount: uint128(credited),
                constraint: constraint
            })
        );
        _bucketDeposits[verifier][constraint][token].push(depositId);
        bucketTotal[verifier][constraint][token] += credited;
        trackedTotal[token] += credited;
        emit Funded(
            depositId,
            funder,
            token,
            credited,
            verifier,
            constraint,
            refundWindow
        );
    }

    function refund(uint256 depositId) external nonReentrant {
        Deposit storage deposit = deposits[depositId];
        if (deposit.funder != msg.sender) revert NotFunder();
        if (deposit.consumed) revert DepositConsumed();
        if (block.timestamp <= uint256(deposit.fundedAt) + deposit.refundWindow)
            revert RefundNotReady();

        _consume(deposit);
        _transfer(deposit.token, msg.sender, deposit.amount);
        emit Refunded(depositId, msg.sender, deposit.token, deposit.amount);
    }

    // ------------------------------------------------------------------ proofs

    /// @notice Present a proof under `verifier` without claiming: sets that verifier's owner
    ///         wallet from it if it is newer than anything seen before, and retires every older
    ///         proof. Call this immediately after moving to a new wallet.
    function refreshProof(
        address verifier,
        bytes calldata proof
    ) external nonReentrant {
        _present(verifier, proof, _noConstraint());
    }

    /// @notice Present a proof and sweep `verifier`'s default bucket for `token` in one call (first claim).
    /// @param depositCountLimit Number of deposit records to visit from the bucket cursor (not
    ///        an amount, not an index); 0 = all. For the default verifier, untracked
    ///        (bare-transfer) funds are always included.
    function refreshProofAndSweep(
        address verifier,
        bytes calldata proof,
        address token,
        uint256 depositCountLimit
    ) external nonReentrant returns (uint256 amount, uint256 consumed) {
        _present(verifier, proof, _noConstraint());
        return _sweepDefault(verifier, token, depositCountLimit);
    }

    // ------------------------------------------------------------------ claiming

    /// @notice Sweep `verifier`'s default bucket for `token` to that verifier's owner. Walks only
    ///         this bucket's list from its cursor; `depositCountLimit` records per call (0 = all).
    ///         When `verifier` is the factory default, untracked funds are included.
    function sweep(
        address verifier,
        address token,
        uint256 depositCountLimit
    )
        external
        nonReentrant
        onlyInitialized(verifier)
        returns (uint256 amount, uint256 consumed)
    {
        return _sweepDefault(verifier, token, depositCountLimit);
    }

    /// @notice Sweep only untracked funds (bare ERC-20 transfers backed by no deposit record) to
    ///         the default verifier's owner.
    function sweepUntracked(
        address token
    ) external nonReentrant returns (uint256 amount) {
        address verifier = defaultVerifier();
        address to = _ownerOf(verifier);
        amount = _untrackedBalance(token);
        if (amount != 0) _transfer(token, to, amount);
        emit Swept(verifier, token, amount, to, 0);
    }

    /// @notice Sweep specific default-bucket deposits of `verifier` by id (e.g. to skip spam in the same bucket).
    function sweepDeposits(
        address verifier,
        address token,
        uint256[] calldata depositIds
    ) external nonReentrant onlyInitialized(verifier) returns (uint256 amount) {
        address to = owner[verifier];
        amount = _consumeIds(verifier, bytes32(0), token, depositIds);
        if (amount != 0) _transfer(token, to, amount);
        emit Swept(verifier, token, amount, to, depositIds.length);
    }

    /// @notice Sweep the bucket funded under `verifier` and `constraint.commitment`. The verifier
    ///         must accept both the identity proof and the constraint evidence; funds go to the
    ///         wallet the proof resolves to. Default buckets (zero commitment) are swept via sweep().
    function sweepBucket(
        address verifier,
        IP2IDVerifier.Constraint calldata constraint,
        address token,
        bytes calldata proof,
        uint256 depositCountLimit
    ) external nonReentrant returns (uint256 amount, uint256 consumed) {
        address to = _verifyForThisVault(verifier, proof, constraint);
        (amount, consumed) = _consumeFromCursor(
            verifier,
            constraint.commitment,
            token,
            depositCountLimit
        );
        if (amount != 0) _transfer(token, to, amount);
        emit SweptBucket(
            verifier,
            constraint.commitment,
            token,
            amount,
            to,
            consumed
        );
    }

    /// @notice Sweep specific deposits of a constrained bucket by id.
    function sweepBucketDeposits(
        address verifier,
        IP2IDVerifier.Constraint calldata constraint,
        address token,
        uint256[] calldata depositIds,
        bytes calldata proof
    ) external nonReentrant returns (uint256 amount) {
        address to = _verifyForThisVault(verifier, proof, constraint);
        amount = _consumeIds(
            verifier,
            constraint.commitment,
            token,
            depositIds
        );
        if (amount != 0) _transfer(token, to, amount);
        emit SweptBucket(
            verifier,
            constraint.commitment,
            token,
            amount,
            to,
            depositIds.length
        );
    }

    // ------------------------------------------------------------------ views

    /// @notice The factory's current default verifier (timelocked there): used by fund() and for untracked funds.
    function defaultVerifier() public view returns (address) {
        return IP2IdVaultFactory(factory).defaultVerifier();
    }

    function depositCount() external view returns (uint256) {
        return deposits.length;
    }

    /// @notice Deposit ids in a bucket, in funding order (consumed ones included; see `deposits`).
    function bucketDepositIds(
        address verifier,
        bytes32 constraint,
        address token
    ) external view returns (uint256[] memory) {
        return _bucketDeposits[verifier][constraint][token];
    }

    function bucketDepositCount(
        address verifier,
        bytes32 constraint,
        address token
    ) external view returns (uint256) {
        return _bucketDeposits[verifier][constraint][token].length;
    }

    /// @notice What `sweep(verifier, token, 0)` would pay now: every unconsumed default deposit
    ///         under `verifier`, plus untracked funds when it is the default verifier.
    function sweepable(
        address verifier,
        address token
    ) external view returns (uint256) {
        uint256 amount = bucketTotal[verifier][bytes32(0)][token];
        if (verifier == defaultVerifier()) amount += _untrackedBalance(token);
        return amount;
    }

    /// @notice Untracked funds only: bare ERC-20 transfers not backed by any deposit record.
    function untrackedBalance(address token) external view returns (uint256) {
        return _untrackedBalance(token);
    }

    // ------------------------------------------------------------------ internals

    /// @dev Every proof enters through here. Requires `verifier` to be approved, verifies the
    ///      proof for this vault's identity (the verifier reverts for any other identity),
    ///      refuses it if older than the newest proof seen under that verifier, and if it is
    ///      newer makes its wallet that verifier's owner. Returns the wallet to pay.
    function _present(
        address verifier,
        bytes calldata proof,
        IP2IDVerifier.Constraint memory constraint
    ) private onlyApprovedVerifier(verifier) returns (address wallet) {
        uint64 iat;
        (wallet, iat) = IP2IDVerifier(verifier).getIdentityWallet(
            saltCommitment,
            proof,
            constraint
        );
        if (wallet == address(0)) revert InvalidWallet();
        uint64 latest = latestProofIat[verifier];
        if (iat < latest) revert ProofTooOld();
        if (iat > latest || owner[verifier] == address(0)) {
            owner[verifier] = wallet;
            latestProofIat[verifier] = iat;
            emit OwnerRefreshed(verifier, wallet, iat);
        }
        // iat == latest with the owner set: same-age proof (a replayed copy, or another wallet
        // slot of the same token); the owner stays, and constrained paths pay `wallet`.
    }

    /// @dev Constrained-bucket entry: default buckets are only reachable through sweep().
    function _verifyForThisVault(
        address verifier,
        bytes calldata proof,
        IP2IDVerifier.Constraint calldata constraint
    ) private returns (address wallet) {
        if (constraint.commitment == bytes32(0)) revert ConstraintRequired();
        return _present(verifier, proof, constraint);
    }

    /// @dev Owner wallet for proof-less default sweeps; the verifier must still be approved.
    function _ownerOf(
        address verifier
    ) private view onlyApprovedVerifier(verifier) returns (address to) {
        to = owner[verifier];
        if (to == address(0)) revert OwnerNotInitialized();
    }

    function _noConstraint()
        private
        pure
        returns (IP2IDVerifier.Constraint memory c)
    {
        c.commitment = bytes32(0);
        c.signature = "";
    }

    /// @dev Default-bucket sweep for one verifier. Pays the default deposits consumed here, plus
    ///      the untracked surplus when `verifier` is the factory default.
    function _sweepDefault(
        address verifier,
        address token,
        uint256 depositCountLimit
    ) private returns (uint256 amount, uint256 consumed) {
        address to = owner[verifier];
        uint256 untracked = verifier == defaultVerifier()
            ? _untrackedBalance(token)
            : 0;
        (amount, consumed) = _consumeFromCursor(
            verifier,
            bytes32(0),
            token,
            depositCountLimit
        );
        amount += untracked;
        if (amount != 0) _transfer(token, to, amount);
        emit Swept(verifier, token, amount, to, consumed);
    }

    function _consumeFromCursor(
        address verifier,
        bytes32 constraint,
        address token,
        uint256 depositCountLimit
    ) private returns (uint256 amount, uint256 consumed) {
        uint256[] storage ids = _bucketDeposits[verifier][constraint][token];
        uint256 i = bucketCursor[verifier][constraint][token];
        uint256 end = ids.length;
        // Bound by records visited, not records consumed: a run of already-consumed records
        // (refunded, or swept by id) is paged through at a fixed cost per call.
        if (depositCountLimit != 0 && end - i > depositCountLimit)
            end = i + depositCountLimit;
        while (i < end) {
            Deposit storage deposit = deposits[ids[i]];
            if (!deposit.consumed) {
                _consume(deposit);
                amount += deposit.amount;
                consumed++;
            }
            i++;
        }
        bucketCursor[verifier][constraint][token] = i;
    }

    function _consumeIds(
        address verifier,
        bytes32 constraint,
        address token,
        uint256[] calldata depositIds
    ) private returns (uint256 amount) {
        for (uint256 k = 0; k < depositIds.length; k++) {
            uint256 id = depositIds[k];
            if (id >= deposits.length) revert DepositNotInBucket(id);
            Deposit storage deposit = deposits[id];
            if (
                deposit.verifier != verifier ||
                deposit.constraint != constraint ||
                deposit.token != token
            ) {
                revert DepositNotInBucket(id);
            }
            if (deposit.consumed) revert DepositConsumed();
            _consume(deposit);
            amount += deposit.amount;
        }
    }

    function _untrackedBalance(address token) private view returns (uint256) {
        uint256 balance = _balanceOf(token);
        uint256 tracked = trackedTotal[token];
        return balance > tracked ? balance - tracked : 0;
    }

    function _consume(Deposit storage deposit) private {
        deposit.consumed = true;
        bucketTotal[deposit.verifier][deposit.constraint][
            deposit.token
        ] -= deposit.amount;
        trackedTotal[deposit.token] -= deposit.amount;
    }

    function _transfer(address token, address to, uint256 amount) private {
        _callToken(
            token,
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
    }

    function _balanceOf(address token) private view returns (uint256 balance) {
        (bool ok, bytes memory data) = token.staticcall(
            abi.encodeWithSignature("balanceOf(address)", address(this))
        );
        if (!ok || data.length != 32) revert TokenBalanceQueryFailed();
        balance = abi.decode(data, (uint256));
    }

    function _callToken(address token, bytes memory input) private {
        (bool ok, bytes memory data) = token.call(input);
        if (
            !ok ||
            (data.length != 0 &&
                (data.length != 32 || !abi.decode(data, (bool))))
        ) revert TokenCallFailed();
    }

    /// @dev The factory's registry decides which verifiers deposits may be funded under and claimed through.
    modifier onlyApprovedVerifier(address verifier) {
        if (!IP2IdVaultFactory(factory).approvedVerifiers(verifier))
            revert VerifierNotApproved(verifier);
        _;
    }

    modifier onlyFactory() {
        if (msg.sender != factory) revert NotFactory();
        _;
    }

    /// @dev Proof-less default-bucket payouts need an owner wallet under an approved verifier.
    modifier onlyInitialized(address verifier) {
        _ownerOf(verifier);
        _;
    }

    modifier nonReentrant() {
        if (reentrancyLock != 1) revert Reentrancy();
        reentrancyLock = 2;
        _;
        reentrancyLock = 1;
    }
}
