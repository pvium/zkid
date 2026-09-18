// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IP2IDVault} from "./interfaces/IP2IDVault.sol";
import {IP2IDVerifier} from "./interfaces/IP2IDVerifier.sol";
import {IP2IDPolicy} from "./interfaces/IP2IDPolicy.sol";
import {IP2IdVaultFactory} from "./interfaces/IP2IdVaultFactory.sol";

/// @title P2IDVault
/// @notice A namespace-bound vault that holds ERC-20 funds until the identity owner claims them.
/// @dev **A bare ERC-20 transfer to this contract is irrevocable: it records no funder, has no
///      refund path, and is claimable only through the factory's default verifier.** Use fund()
///      when refund rights, a funding constraint, or a specific verifier are required.
///
///      This contract holds mechanics only; everything expected to evolve is decided by the
///      factory's policy (IP2IDPolicy), consulted on every call, so it can change without
///      changing this bytecode and therefore without moving any P2ID address. The limits a
///      policy can never cross are enforced here:
///        - fees are capped at MAX_FEE_BPS, fixed per deposit when it is made (a failing quote
///          means no fee), and accrue in the vault per (verifier, token); a payout never calls
///          the policy about fees, so fee handling can never block a claim. withdrawFees hands
///          accrued fees to the current policy, which pulls exactly the approved amount and
///          distributes it;
///        - refunds never pay a fee and never consult the policy;
///        - the policy can gate which verifiers are usable (freezing claims under a disallowed
///          one), but cannot redirect a payout: every claim still pays the wallet the verifier
///          resolved for this vault's identity. Claims through the factory's current default
///          verifier can never be frozen: direct transfers have no refund path, so the only thing
///          that may change who receives them is a default-verifier change with 14 days' notice.
///          (The policy still gates *funding* under the default, so a revoked default takes no
///          new deposits.)
///
///      Verifiers. Every deposit names the IP2IDVerifier whose proofs can release it, chosen by
///      the payer among those the policy allows (fund() takes the factory default). Every claim
///      path hands the verifier this vault's `saltCommitment` plus a proof and gets back the
///      wallet to pay; the verifier reverts unless the proof is for exactly that identity.
///      A constrained deposit is refused under a verifier that cannot satisfy constraints.
///
///      Accounting is per bucket, where a bucket is (verifier, constraint, token) and the
///      default bucket of a verifier is constraint == bytes32(0). Each bucket keeps its own
///      deposit-id list and cursor, so sweeps are bounded per bucket, can be paged
///      (`depositCountLimit` = number of deposit records visited from the cursor, consumed or
///      not; 0 = all) or aimed at specific ids, and spam in other tokens or buckets never blocks
///      a sweep.
///
///      Proof freshness ratchet, per verifier: every proof presented must be at least as fresh
///      as the newest one this vault has seen under that verifier, and a newer proof becomes the
///      owner proof, so presenting a proof for a new wallet retires every older proof. Funds
///      already inside before that reset are not protected: reset immediately after a wallet
///      compromise.
///
///      Direct transfers follow the factory's default verifier, which governance can change after 14
///      days' public notice. So that a change cannot bring back a wallet the owner has already moved away from,
///      direct transfers have their own freshness floor, `untrackedProofIat`: the newest proof
///      presented through whichever verifier was the default at the time. It carries across a
///      default change, and direct transfers are paid only to a default-verifier owner whose proof
///      is at least that fresh. Only the default verifier (chosen by governance, under the
///      timelock) can raise it, so a verifier payers merely opted into cannot affect it.
///
///      Invariant kept by every path: token balance >= trackedTotal[token] + feesOwedTotal[token].
contract P2IDVault is IP2IDVault {
    /// @notice Hard cap on the fee any policy can charge on a payout: 1%. Part of this bytecode.
    uint16 public constant MAX_FEE_BPS = 100;
    uint256 private constant BPS = 10_000;
    /// @dev Gas given to optional policy/verifier queries, so a misbehaving contract cannot burn
    ///      the caller's gas; a query that fails or runs out is treated as "no fee" / "unsupported".
    uint256 private constant QUERY_GAS = 50_000;

    /// @notice Deployer (PviumP2IdVaultFactory): the policy's source, and the only caller of initialize() and fundFor().
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
    /// @notice Freshness floor for direct transfers: the newest proof presented through the verifier
    ///         that was the default at the time. Carries across default changes.
    uint64 public untrackedProofIat;

    /// @notice All deposits ever made, by id.
    Deposit[] public deposits;

    /// @notice Unconsumed total per (verifier, constraint, token) bucket.
    mapping(address verifier => mapping(bytes32 constraint => mapping(address token => uint256))) public bucketTotal;
    /// @notice Sum of all unconsumed deposits per token.
    mapping(address token => uint256) public trackedTotal;
    /// @dev Deposit ids per bucket, in funding order.
    mapping(address verifier => mapping(bytes32 constraint => mapping(address token => uint256[]))) private _bucketDeposits;
    /// @notice Index into the bucket's deposit list below which every deposit is consumed.
    mapping(address verifier => mapping(bytes32 constraint => mapping(address token => uint256))) public bucketCursor;
    /// @notice Fees accrued and not yet distributed, per verifier they were earned through and token.
    mapping(address verifier => mapping(address token => uint256)) public feesOwed;
    /// @notice Sum of feesOwed per token: held for distribution, never part of a payout.
    mapping(address token => uint256) public feesOwedTotal;

    uint256 private reentrancyLock = 1;

    error InvalidRefundWindow();
    error VerifierNotApproved(address verifier);
    error ConstraintsUnsupported(address verifier);
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
    error FeeOverdrawn();

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
        return _fund(msg.sender, defaultVerifier(), token, amount, constraint, refundWindow);
    }

    /// @notice Fund under any verifier the factory's policy allows.
    function fundWith(
        address verifier,
        address token,
        uint256 amount,
        bytes32 constraint,
        uint64 refundWindow
    ) external nonReentrant returns (uint256 depositId) {
        return _fund(msg.sender, verifier, token, amount, constraint, refundWindow);
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

    /// @dev Pull `amount` of `token` from msg.sender and record a deposit owned by `funder`, with
    ///      the fee rate the policy quotes now (capped) fixed for it.
    function _fund(
        address funder,
        address verifier,
        address token,
        uint256 amount,
        bytes32 constraint,
        uint64 refundWindow
    ) private onlyAllowed(verifier) returns (uint256 depositId) {
        if (constraint != bytes32(0) && !_supportsConstraints(verifier)) revert ConstraintsUnsupported(verifier);
        if (token.code.length == 0) revert InvalidToken();
        if (refundWindow < minRefundWindow || refundWindow > maxRefundWindow) revert InvalidRefundWindow();
        if (amount == 0 || amount > type(uint128).max) revert InvalidRefundAmount();

        uint256 beforeBalance = _balanceOf(token);
        _callToken(token, abi.encodeWithSignature("transferFrom(address,address,uint256)", msg.sender, address(this), amount));
        uint256 afterBalance = _balanceOf(token);
        if (afterBalance <= beforeBalance) revert InvalidRefundAmount();
        uint256 credited = afterBalance - beforeBalance;
        if (credited > type(uint128).max) revert AmountTooLarge();

        uint16 feeBps = _quoteFeeBps(verifier, token);
        depositId = deposits.length;
        deposits.push(
            Deposit({
                funder: funder,
                fundedAt: uint64(block.timestamp),
                consumed: false,
                token: token,
                refundWindow: refundWindow,
                verifier: verifier,
                feeBps: feeBps,
                amount: uint128(credited),
                constraint: constraint
            })
        );
        _bucketDeposits[verifier][constraint][token].push(depositId);
        bucketTotal[verifier][constraint][token] += credited;
        trackedTotal[token] += credited;
        emit Funded(depositId, funder, token, credited, verifier, constraint, refundWindow, feeBps);
    }

    /// @notice Return an unconsumed deposit to its funder after its refund window. Never charges a
    ///         fee and never consults the policy.
    function refund(uint256 depositId) external nonReentrant {
        Deposit storage deposit = deposits[depositId];
        if (deposit.funder != msg.sender) revert NotFunder();
        if (deposit.consumed) revert DepositConsumed();
        if (block.timestamp <= uint256(deposit.fundedAt) + deposit.refundWindow) revert RefundNotReady();

        _consume(deposit);
        _transfer(deposit.token, msg.sender, deposit.amount);
        emit Refunded(depositId, msg.sender, deposit.token, deposit.amount);
    }

    // ------------------------------------------------------------------ proofs

    /// @notice Present a proof under `verifier` without claiming: sets that verifier's owner
    ///         wallet from it if it is newer than anything seen before, and retires every older
    ///         proof. Call this immediately after moving to a new wallet.
    function refreshProof(address verifier, bytes calldata proof) external nonReentrant {
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
    function sweep(address verifier, address token, uint256 depositCountLimit)
        external
        nonReentrant
        onlyInitialized(verifier)
        returns (uint256 amount, uint256 consumed)
    {
        return _sweepDefault(verifier, token, depositCountLimit);
    }

    /// @notice Sweep only untracked funds (bare ERC-20 transfers backed by no deposit record) to
    ///         the default verifier's owner. The fee rate is quoted now.
    function sweepUntracked(address token) external nonReentrant returns (uint256 amount) {
        address verifier = defaultVerifier();
        address to = _ownerOf(verifier);
        if (latestProofIat[verifier] < untrackedProofIat) revert ProofTooOld();
        uint256 gross = _untrackedBalance(token);
        uint256 fee = (gross * _quoteFeeBps(verifier, token)) / BPS;
        uint256 charged;
        (amount, charged) = _payout(verifier, token, to, gross, fee);
        emit Swept(verifier, token, amount, charged, to, 0);
    }

    /// @notice Sweep specific default-bucket deposits of `verifier` by id (e.g. to skip spam in the same bucket).
    function sweepDeposits(address verifier, address token, uint256[] calldata depositIds)
        external
        nonReentrant
        onlyInitialized(verifier)
        returns (uint256 amount)
    {
        address to = owner[verifier];
        (uint256 gross, uint256 fee) = _consumeIds(verifier, bytes32(0), token, depositIds, to);
        uint256 charged;
        (amount, charged) = _payout(verifier, token, to, gross, fee);
        emit Swept(verifier, token, amount, charged, to, depositIds.length);
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
        uint256 gross;
        uint256 fee;
        (gross, fee, consumed) = _consumeFromCursor(verifier, constraint.commitment, token, depositCountLimit, to);
        uint256 charged;
        (amount, charged) = _payout(verifier, token, to, gross, fee);
        emit SweptBucket(verifier, constraint.commitment, token, amount, charged, to, consumed);
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
        (uint256 gross, uint256 fee) = _consumeIds(verifier, constraint.commitment, token, depositIds, to);
        uint256 charged;
        (amount, charged) = _payout(verifier, token, to, gross, fee);
        emit SweptBucket(verifier, constraint.commitment, token, amount, charged, to, depositIds.length);
    }

    // ------------------------------------------------------------------ fees

    /// @notice Hand the fees earned through `verifier` in `token` to the current policy, which
    ///         pulls them and distributes them. Anyone may call it: the tokens can only go to the
    ///         policy, and only as much as is owed. Returns the amount the policy took.
    function withdrawFees(address verifier, address token) external nonReentrant returns (uint256 amount) {
        uint256 owed = feesOwed[verifier][token];
        if (owed == 0) return 0;
        address pol = policy();
        uint256 before = _balanceOf(token);
        _callToken(token, abi.encodeWithSignature("approve(address,uint256)", pol, owed));
        IP2IDPolicy(pol).distributeFee(verifier, token, owed);
        _callToken(token, abi.encodeWithSignature("approve(address,uint256)", pol, 0));
        uint256 afterBalance = _balanceOf(token);
        amount = before > afterBalance ? before - afterBalance : 0;
        if (amount > owed) revert FeeOverdrawn();
        feesOwed[verifier][token] = owed - amount;
        feesOwedTotal[token] -= amount;
        emit FeesDistributed(verifier, token, amount, pol);
    }

    // ------------------------------------------------------------------ views

    /// @notice The factory's current policy (replaceable there only through a timelock).
    function policy() public view returns (address) {
        return IP2IdVaultFactory(factory).policy();
    }

    /// @notice The factory's current default verifier (timelocked there): used by fund() and for untracked funds.
    function defaultVerifier() public view returns (address) {
        return IP2IdVaultFactory(factory).defaultVerifier();
    }

    function depositCount() external view returns (uint256) {
        return deposits.length;
    }

    /// @notice Deposit ids in a bucket, in funding order (consumed ones included; see `deposits`).
    function bucketDepositIds(address verifier, bytes32 constraint, address token) external view returns (uint256[] memory) {
        return _bucketDeposits[verifier][constraint][token];
    }

    function bucketDepositCount(address verifier, bytes32 constraint, address token) external view returns (uint256) {
        return _bucketDeposits[verifier][constraint][token].length;
    }

    /// @notice Gross amount `sweep(verifier, token, 0)` would release now, before fees: every
    ///         unconsumed default deposit under `verifier`, plus untracked funds when it is the default verifier.
    function sweepable(address verifier, address token) external view returns (uint256) {
        uint256 amount = bucketTotal[verifier][bytes32(0)][token];
        if (_paysUntracked(verifier)) amount += _untrackedBalance(token);
        return amount;
    }

    /// @notice Untracked funds only: bare ERC-20 transfers not backed by any deposit record.
    function untrackedBalance(address token) external view returns (uint256) {
        return _untrackedBalance(token);
    }

    // ------------------------------------------------------------------ internals

    /// @dev Every proof enters through here. Requires `verifier` to be allowed, verifies the proof
    ///      for this vault's identity (the verifier reverts for any other identity), refuses it if
    ///      older than the newest proof seen under that verifier, and if it is newer makes its
    ///      wallet that verifier's owner. Returns the wallet to pay.
    function _present(
        address verifier,
        bytes calldata proof,
        IP2IDVerifier.Constraint memory constraint
    ) private onlyClaimable(verifier) returns (address wallet) {
        uint64 iat;
        (wallet, iat) = IP2IDVerifier(verifier).getIdentityWallet(saltCommitment, proof, constraint);
        if (wallet == address(0)) revert InvalidWallet();
        uint64 latest = latestProofIat[verifier];
        if (iat < latest) revert ProofTooOld();
        if (iat > latest || owner[verifier] == address(0)) {
            owner[verifier] = wallet;
            latestProofIat[verifier] = iat;
            emit OwnerRefreshed(verifier, wallet, iat);
        }
        if (iat > untrackedProofIat && verifier == defaultVerifier()) untrackedProofIat = iat;
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

    /// @dev Direct transfers go to `verifier`'s owner only if it is the current default and its
    ///      owner proof is at least as fresh as the newest proof any default has seen.
    function _paysUntracked(address verifier) private view returns (bool) {
        return verifier == defaultVerifier() && latestProofIat[verifier] >= untrackedProofIat;
    }

    /// @dev Owner wallet for proof-less default sweeps; the verifier must still be claimable.
    function _ownerOf(address verifier) private view onlyClaimable(verifier) returns (address to) {
        to = owner[verifier];
        if (to == address(0)) revert OwnerNotInitialized();
    }

    function _noConstraint() private pure returns (IP2IDVerifier.Constraint memory c) {
        c.commitment = bytes32(0);
        c.signature = "";
    }

    /// @dev Default-bucket sweep for one verifier: the default deposits consumed here at their
    ///      fixed rates, plus the untracked surplus (at the rate quoted now) when `verifier` is the
    ///      factory default.
    function _sweepDefault(address verifier, address token, uint256 depositCountLimit)
        private
        returns (uint256 amount, uint256 consumed)
    {
        address to = owner[verifier];
        uint256 untracked = _paysUntracked(verifier) ? _untrackedBalance(token) : 0;
        uint256 gross;
        uint256 fee;
        (gross, fee, consumed) = _consumeFromCursor(verifier, bytes32(0), token, depositCountLimit, to);
        if (untracked != 0) {
            gross += untracked;
            fee += (untracked * _quoteFeeBps(verifier, token)) / BPS;
        }
        uint256 charged;
        (amount, charged) = _payout(verifier, token, to, gross, fee);
        emit Swept(verifier, token, amount, charged, to, consumed);
    }

    function _consumeFromCursor(
        address verifier,
        bytes32 constraint,
        address token,
        uint256 depositCountLimit,
        address to
    ) private returns (uint256 amount, uint256 fee, uint256 consumed) {
        uint256[] storage ids = _bucketDeposits[verifier][constraint][token];
        uint256 i = bucketCursor[verifier][constraint][token];
        uint256 end = ids.length;
        // Bound by records visited, not records consumed: a run of already-consumed records
        // (refunded, or swept by id) is paged through at a fixed cost per call.
        if (depositCountLimit != 0 && end - i > depositCountLimit) end = i + depositCountLimit;
        while (i < end) {
            uint256 id = ids[i];
            Deposit storage deposit = deposits[id];
            if (!deposit.consumed) {
                (uint256 a, uint256 f) = _claim(id, deposit, to);
                amount += a;
                fee += f;
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
        uint256[] calldata depositIds,
        address to
    ) private returns (uint256 amount, uint256 fee) {
        for (uint256 k = 0; k < depositIds.length; k++) {
            uint256 id = depositIds[k];
            if (id >= deposits.length) revert DepositNotInBucket(id);
            Deposit storage deposit = deposits[id];
            if (deposit.verifier != verifier || deposit.constraint != constraint || deposit.token != token) {
                revert DepositNotInBucket(id);
            }
            if (deposit.consumed) revert DepositConsumed();
            (uint256 a, uint256 f) = _claim(id, deposit, to);
            amount += a;
            fee += f;
        }
    }

    /// @dev Consume a deposit for a payout to `to`; its fee is computed at the rate fixed at funding.
    function _claim(uint256 id, Deposit storage deposit, address to) private returns (uint256 amount, uint256 fee) {
        _consume(deposit);
        amount = deposit.amount;
        fee = (amount * deposit.feeBps) / BPS;
        emit Claimed(id, to, amount, fee);
    }

    /// @dev Pay `gross - fee` to `to` and keep `fee` accrued for `verifier`. No policy call.
    ///      Returns (net paid, fee charged).
    function _payout(address verifier, address token, address to, uint256 gross, uint256 fee)
        private
        returns (uint256 net, uint256 charged)
    {
        if (fee != 0) {
            charged = fee;
            feesOwed[verifier][token] += fee;
            feesOwedTotal[token] += fee;
            emit FeeAccrued(verifier, token, fee);
        }
        net = gross - charged;
        if (net != 0) _transfer(token, to, net);
    }

    function _untrackedBalance(address token) private view returns (uint256) {
        uint256 balance = _balanceOf(token);
        uint256 held = trackedTotal[token] + feesOwedTotal[token];
        return balance > held ? balance - held : 0;
    }

    function _consume(Deposit storage deposit) private {
        deposit.consumed = true;
        bucketTotal[deposit.verifier][deposit.constraint][deposit.token] -= deposit.amount;
        trackedTotal[deposit.token] -= deposit.amount;
    }

    // ------------------------------------------------------------------ policy / verifier queries

    function _policy() private view returns (IP2IDPolicy) {
        return IP2IDPolicy(IP2IdVaultFactory(factory).policy());
    }

    /// @dev The policy's fee rate for (verifier, token), capped at MAX_FEE_BPS; 0 if the query fails.
    function _quoteFeeBps(address verifier, address token) private view returns (uint16) {
        (bool ok, uint256 v) = _query(address(_policy()), abi.encodeCall(IP2IDPolicy.feeBps, (verifier, token)));
        if (!ok) return 0;
        return v > MAX_FEE_BPS ? MAX_FEE_BPS : uint16(v);
    }

    /// @dev Whether `verifier` declares it can satisfy constraints; false if it does not say.
    function _supportsConstraints(address verifier) private view returns (bool) {
        (bool ok, uint256 v) = _query(verifier, abi.encodeCall(IP2IDVerifier.supportsConstraints, ()));
        return ok && v == 1;
    }

    /// @dev Gas-capped static call expecting one 32-byte word; (false, 0) on any failure.
    function _query(address target, bytes memory data) private view returns (bool ok, uint256 value) {
        bytes memory ret;
        (ok, ret) = target.staticcall{gas: QUERY_GAS}(data);
        if (!ok || ret.length != 32) return (false, 0);
        value = abi.decode(ret, (uint256));
    }

    // ------------------------------------------------------------------ tokens

    function _transfer(address token, address to, uint256 amount) private {
        _callToken(token, abi.encodeWithSignature("transfer(address,uint256)", to, amount));
    }

    function _balanceOf(address token) private view returns (uint256 balance) {
        (bool ok, bytes memory data) = token.staticcall(abi.encodeWithSignature("balanceOf(address)", address(this)));
        if (!ok || data.length != 32) revert TokenBalanceQueryFailed();
        balance = abi.decode(data, (uint256));
    }

    function _callToken(address token, bytes memory input) private {
        (bool ok, bytes memory data) = token.call(input);
        if (!ok || (data.length != 0 && (data.length != 32 || !abi.decode(data, (bool))))) revert TokenCallFailed();
    }

    // ------------------------------------------------------------------ modifiers

    /// @dev Funding: the policy decides which verifiers new deposits may be made under.
    modifier onlyAllowed(address verifier) {
        if (!_policy().isVerifierAllowed(verifier)) revert VerifierNotApproved(verifier);
        _;
    }

    /// @dev Claiming: through the factory's current default verifier always (see the contract
    ///      notes), otherwise only while the policy allows the verifier.
    modifier onlyClaimable(address verifier) {
        if (verifier != defaultVerifier() && !_policy().isVerifierAllowed(verifier)) revert VerifierNotApproved(verifier);
        _;
    }

    modifier onlyFactory() {
        if (msg.sender != factory) revert NotFactory();
        _;
    }

    /// @dev Proof-less default-bucket payouts need an owner wallet under an allowed verifier.
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
