import unittest

from pydantic import ValidationError

try:
    import app.main as main
except ModuleNotFoundError:
    main = None


@unittest.skipIf(main is None, "FastAPI app dependencies are not installed")
class ApiGuardrailTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous_token = main.API_TOKEN

    def tearDown(self) -> None:
        main.API_TOKEN = self.previous_token

    def test_mutating_routes_require_token_when_configured(self) -> None:
        main.API_TOKEN = "secret"

        with self.assertRaises(main.HTTPException) as context:
            main.require_api_token()

        self.assertEqual(context.exception.status_code, 401)
        self.assertIsNone(main.require_api_token(x_api_token="secret"))

    def test_live_start_rejects_excessive_scan_parameters(self) -> None:
        with self.assertRaises(ValidationError):
            main.LiveStartRequest(
                rpc_url="https://rpc.flashbots.net",
                chain_id=1,
                poll_interval=20,
                lookback_blocks=main.MAX_LOOKBACK_BLOCKS + 1,
                max_blocks_per_tick=12,
            )


if __name__ == "__main__":
    unittest.main()
