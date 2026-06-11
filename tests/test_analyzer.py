import unittest

from app.analyzer import analyze_source


class AnalyzerHeuristicTests(unittest.TestCase):
    def test_functions_include_full_body_for_ui_expansion(self) -> None:
        report = analyze_source(
            """
            pragma solidity ^0.8.0;
            contract Vault {
                mapping(address => uint256) public balances;

                function withdraw() external {
                    uint256 amount = balances[msg.sender];
                    balances[msg.sender] = 0;
                    (bool ok,) = msg.sender.call{value: amount}("");
                    require(ok);
                }
            }
            """
        ).to_dict()

        withdraw = next(fn for fn in report["functions"] if fn["name"] == "withdraw")
        self.assertEqual(withdraw["visibility"], "external")
        self.assertIn("function withdraw() external", withdraw["body"])
        self.assertIn("balances[msg.sender] = 0;", withdraw["body"])
        self.assertGreater(withdraw["end_line"], withdraw["start_line"])

    def test_account_bound_pull_payment_is_not_high_alert(self) -> None:
        report = analyze_source(
            """
            pragma solidity ^0.8.0;
            contract Bank {
                mapping(address => uint256) public balances;

                function withdraw() external {
                    uint256 amount = balances[msg.sender];
                    require(amount > 0);
                    balances[msg.sender] = 0;
                    (bool ok,) = msg.sender.call{value: amount}("");
                    require(ok);
                }
            }
            """
        ).to_dict()

        self.assertEqual(report["risk"], "MEDIUM")
        self.assertNotIn(
            "Public withdrawal path without obvious access control",
            {finding["title"] for finding in report["findings"]},
        )

    def test_external_call_before_balance_update_is_critical(self) -> None:
        report = analyze_source(
            """
            pragma solidity ^0.8.0;
            contract Bank {
                mapping(address => uint256) public balances;

                function withdraw() external {
                    uint256 amount = balances[msg.sender];
                    (bool ok,) = msg.sender.call{value: amount}("");
                    require(ok);
                    balances[msg.sender] = 0;
                }
            }
            """
        ).to_dict()

        self.assertEqual(report["risk"], "CRITICAL")
        self.assertIn("Possible Reentrancy", {finding["title"] for finding in report["findings"]})

    def test_open_full_balance_sweep_stays_critical(self) -> None:
        report = analyze_source(
            """
            pragma solidity ^0.8.0;
            contract Drain {
                function sweep() external {
                    (bool ok,) = msg.sender.call{value: address(this).balance}("");
                    require(ok);
                }
            }
            """
        ).to_dict()

        self.assertEqual(report["risk"], "CRITICAL")
        titles = {finding["title"] for finding in report["findings"]}
        self.assertIn("Function may drain entire contract balance", titles)

    def test_standard_erc20_transfer_from_is_not_public_withdrawal(self) -> None:
        report = analyze_source(
            """
            pragma solidity ^0.8.0;
            contract Token {
                mapping(address => uint256) private _balances;
                mapping(address => mapping(address => uint256)) private _allowances;

                function transferFrom(address from, address to, uint256 value) public virtual returns (bool) {
                    address spender = msg.sender;
                    _spendAllowance(from, spender, value);
                    _transfer(from, to, value);
                    return true;
                }

                function _spendAllowance(address owner, address spender, uint256 value) internal {
                    uint256 currentAllowance = _allowances[owner][spender];
                    require(currentAllowance >= value);
                    _allowances[owner][spender] = currentAllowance - value;
                }

                function _transfer(address from, address to, uint256 value) internal {
                    require(_balances[from] >= value);
                    _balances[from] -= value;
                    _balances[to] += value;
                }
            }
            """
        ).to_dict()

        self.assertNotIn(
            "Public withdrawal path without obvious access control",
            {finding["title"] for finding in report["findings"]},
        )

    def test_standard_erc20_transfer_is_not_public_withdrawal(self) -> None:
        report = analyze_source(
            """
            pragma solidity ^0.8.0;
            contract Token {
                mapping(address => uint256) private _balances;

                function transfer(address to, uint256 value) public virtual returns (bool) {
                    address owner = msg.sender;
                    _transfer(owner, to, value);
                    return true;
                }

                function _transfer(address from, address to, uint256 value) internal {
                    require(_balances[from] >= value);
                    _balances[from] -= value;
                    _balances[to] += value;
                }
            }
            """
        ).to_dict()

        self.assertNotIn(
            "Public withdrawal path without obvious access control",
            {finding["title"] for finding in report["findings"]},
        )


if __name__ == "__main__":
    unittest.main()
