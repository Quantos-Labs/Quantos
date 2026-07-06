// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title MemecoinToken — ERC20 for Vybss memecoin launchpad
/// @notice Deploys with 1B supply minted to the launchpad contract.
contract MemecoinToken {

    // ── Solang 0.3.3 workaround ────────────────────────────────
    function _add(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; }
    function _sub(uint256 a, uint256 b) internal pure returns (uint256) { return a - b; }

    string  public name;
    string  public symbol;
    uint8   public constant decimals = 18;

    uint256 public constant TOTAL_SUPPLY = 1000000000000000000000000000; // 1B * 1e18

    uint256 private _totalSupply;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /// @param _name   Token name  (e.g. "DogWifRocket")
    /// @param _symbol Token ticker (e.g. "DWRF")
    /// @param _mintTo Address that receives the full 1B supply (= launchpad)
    constructor(string memory _name, string memory _symbol, address _mintTo) {
        name   = _name;
        symbol = _symbol;
        _totalSupply     = TOTAL_SUPPLY;
        _balances[_mintTo] = TOTAL_SUPPLY;
        emit Transfer(address(0), _mintTo, TOTAL_SUPPLY);
    }

    // ── ERC20 standard ──────────────────────────────────────────

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function allowance(address owner, address spender) external view returns (uint256) {
        return _allowances[owner][spender];
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 cur = _allowances[from][msg.sender];
        require(cur >= amount, "Insufficient allowance");
        _approve(from, msg.sender, _sub(cur, amount));
        _transfer(from, to, amount);
        return true;
    }

    // ── Internal ────────────────────────────────────────────────

    function _transfer(address from, address to, uint256 amount) private {
        require(from != address(0), "Transfer from zero");
        require(to   != address(0), "Transfer to zero");
        require(_balances[from] >= amount, "Insufficient balance");
        _balances[from] = _sub(_balances[from], amount);
        _balances[to]   = _add(_balances[to],   amount);
        emit Transfer(from, to, amount);
    }

    function _approve(address owner, address spender, uint256 amount) private {
        require(owner   != address(0), "Approve from zero");
        require(spender != address(0), "Approve to zero");
        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }
}
