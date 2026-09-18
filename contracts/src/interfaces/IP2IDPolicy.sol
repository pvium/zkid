// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title IP2IDPolicy
/// @notice Everything about P2ID vaults that is expected to evolve lives behind this interface,
///         so it can change without changing vault bytecode (and therefore without moving any
///         P2ID address). The vault factory points at one policy and can replace it only through
///         a timelock; every vault consults the factory's current policy on each call.
///
///         What a policy decides, and the limits the vault enforces on it:
///         - which verifiers deposits may be funded under and claimed through. Gating is the one
///           thing a policy can use to stop claims (by disallowing a verifier), which freezes
///           claims under it but never moves funds; refunds never consult the policy.
///         - the protocol fee on payouts, in basis points. The vault caps it at its own
///           MAX_FEE_BPS, fixes a deposit's rate when the deposit is made, never charges it on
///           refunds, and treats a failing quote as no fee.
///         - how accrued fees are distributed. Fees accrue in each vault per (verifier, token);
///           anyone can have a vault hand them to the policy (withdrawFees), which pulls them and
///           splits them however it chooses, e.g. between a verifier's operator and the protocol.
///
///         Launch policy: an owner-managed verifier allowlist and no fee. Permissionless,
///         stake-based verifier registration and fees are later policies.
interface IP2IDPolicy {
    /// @notice Whether deposits may be funded under, and claimed through, `verifier`.
    function isVerifierAllowed(address verifier) external view returns (bool);

    /// @notice Fee on paying out `token` claimed through `verifier`, in basis points. Quoted when a
    ///         deposit is made (and fixed for it), or at sweep time for untracked funds.
    function feeBps(address verifier, address token) external view returns (uint16);

    /// @notice Called by a vault holding fees earned through `verifier`, after approving this
    ///         policy for exactly `amount` of `token`. Pull the tokens (transferFrom the caller)
    ///         and distribute them. Whatever is not pulled stays accrued in the vault; the
    ///         allowance is reset afterwards. Pulling from msg.sender makes the amount
    ///         self-verifying: a caller that is not a vault can only give away its own tokens.
    function distributeFee(address verifier, address token, uint256 amount) external;
}
