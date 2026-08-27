import unittest
from unittest.mock import patch
import logging

# Check if required dependencies are available
try:
    import pydantic_settings
    import pydantic
    HAS_DEPENDENCIES = True
except ImportError:
    import sys
    from unittest.mock import MagicMock

    # Mock pydantic and pydantic_settings for environments without them
    mock_pydantic = MagicMock()
    mock_pydantic_settings = MagicMock()

    class MockBaseSettings:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        def __getattr__(self, item):
            return None

    mock_pydantic_settings.BaseSettings = MockBaseSettings
    sys.modules['pydantic'] = mock_pydantic
    sys.modules['pydantic_settings'] = mock_pydantic_settings
    HAS_DEPENDENCIES = True

class TestSettings(unittest.TestCase):

    def setUp(self):
        # We only import Settings here so that if dependencies are missing,
        # it doesn't crash during test discovery.
        from config.settings import Settings, Environment, LatencyBudget
        self.Settings = Settings
        self.Environment = Environment
        self.LatencyBudget = LatencyBudget

    def test_default_settings(self):
        """Test that default settings are correctly applied."""
        settings = self.Settings()

        self.assertEqual(settings.ENV, self.Environment.DEVELOPMENT)
        self.assertTrue(settings.DEBUG)
        self.assertEqual(settings.LOG_LEVEL, "INFO")
        self.assertTrue(settings.BLOCK_MODE)
        self.assertFalse(settings.REQUIRE_TLS)
        self.assertEqual(settings.MAX_SYNC_LATENCY_MS, self.LatencyBudget.TOTAL_SYNC)

    @patch('logging.critical')
    def test_production_defaults(self, mock_logging):
        """Test that production settings override defaults correctly."""
        settings = self.Settings(
            ENV=self.Environment.PRODUCTION,
            REQUIRE_TLS=False,
            SESSION_STORAGE_TYPE="redis",
            REDIS_PASSWORD=None
        )

        # DEBUG should be forced to False
        self.assertFalse(settings.DEBUG)

        # REQUIRE_API_AUTH should be forced to True
        self.assertTrue(settings.REQUIRE_API_AUTH)

        # REQUIRE_TLS should be forced to True
        self.assertTrue(settings.REQUIRE_TLS)

        # BLOCK_MODE should be True by default in production
        self.assertTrue(settings.BLOCK_MODE)

        # Logging checks
        # Should warn about TLS and Redis password
        self.assertEqual(mock_logging.call_count, 2)

        warnings = [call[0][0] for call in mock_logging.call_args_list]
        self.assertTrue(any("TLS disabled in production" in w for w in warnings))
        self.assertTrue(any("Redis password not set in production" in w for w in warnings))

    @patch('logging.critical')
    def test_block_mode_overwritten_in_production(self, mock_logging):
        """Test that block_mode is forced to True in production."""
        settings = self.Settings(
            ENV=self.Environment.PRODUCTION,
            BLOCK_MODE=False
        )

        # Should be forced to True
        self.assertTrue(settings.BLOCK_MODE)

        # Should log a warning
        warnings = [call[0][0] for call in mock_logging.call_args_list]
        self.assertTrue(any("Block mode disabled in production" in w for w in warnings))

    @patch('logging.critical')
    def test_production_secure_overrides_not_warned_if_set(self, mock_logging):
        """Test that warnings aren't triggered if secure settings are provided."""
        settings = self.Settings(
            ENV=self.Environment.PRODUCTION,
            REQUIRE_TLS=True,
            SESSION_STORAGE_TYPE="redis",
            REDIS_PASSWORD="secure_password_here"
        )

        # Debug and API auth still forced
        self.assertFalse(settings.DEBUG)
        self.assertTrue(settings.REQUIRE_API_AUTH)
        self.assertTrue(settings.REQUIRE_TLS)

        # No critical warnings should be logged
        mock_logging.assert_not_called()

if __name__ == '__main__':
    unittest.main()
