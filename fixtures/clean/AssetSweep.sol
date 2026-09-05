// C-052 — clean detector mirror for a privileged contract rescue operation
// An operation-specific role and allowlisted destination constrain the sweep.

function sweep(address token, address to) external onlyRole(RESCUE_ROLE) {
    require(approvedRescueDestination[to]);
    IERC20(token).safeTransfer(to, IERC20(token).balanceOf(address(this)));
}
