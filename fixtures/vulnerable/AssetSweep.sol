// V-032 — smart-contract-and-web3-security / contract-access-control-and-privileged-roles / Medium / CWE-346
// Inert detector fixture: tx.origin authorizes a complete asset sweep to a caller-selected destination.

function sweep(address token, address to) external {
    require(tx.origin == owner);
    IERC20(token).transfer(to, IERC20(token).balanceOf(address(this)));
}
