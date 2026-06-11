import unittest

from app.llm import OllamaAuditClient


class LlmPromptTests(unittest.TestCase):
    def test_prompt_is_english_and_includes_heuristic_context(self) -> None:
        prompt = OllamaAuditClient().build_prompt(
            "contract Vault { function withdraw() external {} }",
            {
                "risk": "CRITICAL",
                "findings": [
                    {
                        "severity": "CRITICAL",
                        "title": "Possible Reentrancy",
                        "function": "withdraw()",
                    }
                ],
            },
        )

        self.assertIn("You are a senior Solidity security auditor.", prompt)
        self.assertIn("Identify false positives", prompt)
        self.assertIn("Possible Reentrancy", prompt)
        self.assertIn("contract Vault", prompt)
        self.assertNotIn("po polsku", prompt.lower())


if __name__ == "__main__":
    unittest.main()
