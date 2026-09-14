// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

interface IP2IDIdentityVerifier {
    struct PotContext {
        bytes32 nsHash;
        bytes32 commitment;
        address pot;
    }

    function verifyIdentity(
        PotContext calldata context,
        bytes calldata proofData
    ) external view returns (bytes4 magic, address wallet, uint64 iat);
}

interface IP2IDConstraintVerifier {
    struct PotContext {
        bytes32 nsHash;
        bytes32 commitment;
        address pot;
    }

    function isValidSweep(
        PotContext calldata context,
        address owner,
        address token,
        bytes calldata verifierData
    ) external view returns (bytes4 magic);
}

/// @title P2IDProxy
/// @notice A namespace-bound pot that holds ERC-20 funds until the identity owner claims them.
/// @dev **A bare ERC-20 transfer to this contract is irrevocable: it records no funder, has no
///      refund path, and is claimable only under the namespace default rules.** Use fund() when
///      refund rights or a constraint verifier are required.
contract P2IDProxy {
    bytes4 public constant VERIFY_IDENTITY_MAGIC =
        bytes4(keccak256("P2ID.verifyIdentity.v1"));
    bytes4 public constant VALID_SWEEP_MAGIC =
        bytes4(keccak256("P2ID.isValidSweep.v1"));

    uint256 private constant MAX_VERIFIER_RETURNDATA = 96;

    bytes32 public immutable nsHash;
    bytes32 public immutable saltCommitment;
    IP2IDIdentityVerifier public immutable defaultVerifier;
    uint64 public immutable minRefundWindow;
    uint64 public immutable maxRefundWindow;

    address public owner;
    uint64 public ownerProofIat;

    struct Deposit {
        address funder;
        address verifier;
        address token;
        uint128 amount;
        uint64 fundedAt;
        uint64 refundWindow;
        bool consumed;
    }

    Deposit[] public deposits;
    mapping(address verifier => mapping(address token => uint256))
        public bucketTotal;

    uint256 private reentrancyLock = 1;

    error InvalidRefundWindow();
    error InvalidDefaultVerifier();
    error InvalidRefundAmount();
    error InvalidToken();
    error OwnerNotInitialized();
    error OwnerAlreadyInitialized();
    error OwnerProofTooOld();
    error NotFunder();
    error DepositConsumed();
    error RefundNotReady();
    error VerifierHasNoCode();
    error VerifierCallFailed();
    error InvalidVerifierResult();
    error TokenCallFailed();
    error TokenBalanceQueryFailed();
    error AmountTooLarge();
    error Reentrancy();

    event Funded(
        uint256 indexed depositId,
        address indexed funder,
        address indexed token,
        uint256 amount,
        address verifier,
        uint64 refundWindow
    );
    event Refunded(
        uint256 indexed depositId,
        address indexed funder,
        address indexed token,
        uint256 amount
    );
    event OwnerInitialized(address indexed owner, uint64 iat);
    event Swept(address indexed token, uint256 amount, address indexed owner);
    event SweptBucket(
        address indexed verifier,
        address indexed token,
        uint256 amount,
        address indexed owner
    );

    constructor(
        bytes32 _nsHash,
        bytes32 _saltCommitment,
        address _defaultVerifier,
        uint64 _minRefundWindow,
        uint64 _maxRefundWindow
    ) {
        if (_defaultVerifier.code.length == 0) revert InvalidDefaultVerifier();
        if (_minRefundWindow > _maxRefundWindow) revert InvalidRefundWindow();
        nsHash = _nsHash;
        saltCommitment = _saltCommitment;
        defaultVerifier = IP2IDIdentityVerifier(_defaultVerifier);
        minRefundWindow = _minRefundWindow;
        maxRefundWindow = _maxRefundWindow;
    }

    function fund(
        address token,
        uint256 amount,
        address constraintVerifier,
        uint64 refundWindow
    ) external nonReentrant returns (uint256 depositId) {
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
                funder: msg.sender,
                verifier: constraintVerifier,
                token: token,
                amount: uint128(credited),
                fundedAt: uint64(block.timestamp),
                refundWindow: refundWindow,
                consumed: false
            })
        );
        bucketTotal[constraintVerifier][token] += credited;
        emit Funded(
            depositId,
            msg.sender,
            token,
            credited,
            constraintVerifier,
            refundWindow
        );
    }

    function refund(uint256 depositId) external nonReentrant {
        Deposit storage deposit = deposits[depositId];
        if (deposit.funder != msg.sender) revert NotFunder();
        if (deposit.consumed) revert DepositConsumed();
        if (block.timestamp <= uint256(deposit.fundedAt) + deposit.refundWindow)
            revert RefundNotReady();

        deposit.consumed = true;
        bucketTotal[deposit.verifier][deposit.token] -= deposit.amount;
        _callToken(
            deposit.token,
            abi.encodeWithSignature(
                "transfer(address,uint256)",
                msg.sender,
                deposit.amount
            )
        );
        emit Refunded(depositId, msg.sender, deposit.token, deposit.amount);
    }

    function initializeOwner(bytes calldata proofData) external nonReentrant {
        (bytes4 magic, address provenWallet, uint64 iat) = _verifyIdentity(
            proofData
        );
        if (magic != VERIFY_IDENTITY_MAGIC || provenWallet == address(0))
            revert InvalidVerifierResult();
        if (iat <= ownerProofIat) revert OwnerProofTooOld();

        owner = provenWallet;
        ownerProofIat = iat;
        emit OwnerInitialized(provenWallet, iat);
    }

    function sweep(address token) external nonReentrant {
        address currentOwner = owner;
        if (currentOwner == address(0)) revert OwnerNotInitialized();

        uint256 balance = _balanceOf(token);
        uint256 protectedAmount = _protectedAmount(token);
        uint256 amount = balance - protectedAmount;

        for (uint256 i = 0; i < deposits.length; i++) {
            Deposit storage deposit = deposits[i];
            if (
                !deposit.consumed &&
                deposit.token == token &&
                deposit.verifier == address(0)
            ) {
                deposit.consumed = true;
                bucketTotal[address(0)][token] -= deposit.amount;
            }
        }

        if (amount != 0)
            _callToken(
                token,
                abi.encodeWithSignature(
                    "transfer(address,uint256)",
                    currentOwner,
                    amount
                )
            );
        emit Swept(token, amount, currentOwner);
    }

    function sweepBucket(
        address verifier,
        address token,
        bytes calldata verifierData
    ) external nonReentrant {
        address currentOwner = owner;
        if (currentOwner == address(0)) revert OwnerNotInitialized();
        if (verifier.code.length == 0) revert VerifierHasNoCode();
        _requireValidSweep(verifier, currentOwner, token, verifierData);

        uint256 amount = bucketTotal[verifier][token];
        bucketTotal[verifier][token] = 0;
        for (uint256 i = 0; i < deposits.length; i++) {
            Deposit storage deposit = deposits[i];
            if (
                !deposit.consumed &&
                deposit.token == token &&
                deposit.verifier == verifier
            ) deposit.consumed = true;
        }

        if (amount != 0)
            _callToken(
                token,
                abi.encodeWithSignature(
                    "transfer(address,uint256)",
                    currentOwner,
                    amount
                )
            );
        emit SweptBucket(verifier, token, amount, currentOwner);
    }

    function potContext()
        public
        view
        returns (IP2IDIdentityVerifier.PotContext memory)
    {
        return
            IP2IDIdentityVerifier.PotContext({
                nsHash: nsHash,
                commitment: saltCommitment,
                pot: address(this)
            });
    }

    function _verifyIdentity(
        bytes calldata proofData
    ) private view returns (bytes4 magic, address provenWallet, uint64 iat) {
        bytes memory input = abi.encodeWithSelector(
            IP2IDIdentityVerifier.verifyIdentity.selector,
            potContext(),
            proofData
        );
        bytes memory output = _staticCall(
            address(defaultVerifier),
            input,
            MAX_VERIFIER_RETURNDATA
        );
        if (output.length != 96) revert InvalidVerifierResult();
        (magic, provenWallet, iat) = abi.decode(
            output,
            (bytes4, address, uint64)
        );
    }

    function _requireValidSweep(
        address verifier,
        address currentOwner,
        address token,
        bytes calldata verifierData
    ) private view {
        bytes memory input = abi.encodeWithSelector(
            IP2IDConstraintVerifier.isValidSweep.selector,
            potContext(),
            currentOwner,
            token,
            verifierData
        );
        bytes memory output = _staticCall(verifier, input, 32);
        if (
            output.length != 32 ||
            abi.decode(output, (bytes4)) != VALID_SWEEP_MAGIC
        ) revert InvalidVerifierResult();
    }

    function _protectedAmount(
        address token
    ) private view returns (uint256 protectedAmount) {
        for (uint256 i = 0; i < deposits.length; i++) {
            Deposit storage deposit = deposits[i];
            if (
                !deposit.consumed &&
                deposit.token == token &&
                deposit.verifier != address(0)
            ) {
                protectedAmount += deposit.amount;
            }
        }
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

    function _staticCall(
        address target,
        bytes memory input,
        uint256 maxOutput
    ) private view returns (bytes memory output) {
        if (target.code.length == 0) revert VerifierHasNoCode();
        bool ok;
        uint256 outputSize;
        assembly {
            ok := staticcall(
                gas(),
                target,
                add(input, 0x20),
                mload(input),
                0,
                0
            )
            outputSize := returndatasize()
        }
        if (!ok) revert VerifierCallFailed();
        if (outputSize > maxOutput) revert InvalidVerifierResult();
        output = new bytes(outputSize);
        assembly {
            returndatacopy(add(output, 0x20), 0, outputSize)
        }
    }

    modifier nonReentrant() {
        if (reentrancyLock != 1) revert Reentrancy();
        reentrancyLock = 2;
        _;
        reentrancyLock = 1;
    }
}
