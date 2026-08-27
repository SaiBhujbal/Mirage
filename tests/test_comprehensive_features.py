import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Mock numpy for environments without it
sys.modules['numpy'] = MagicMock()

# Import the module under test
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.comprehensive_features import extract_features

class TestExtractFeatures(unittest.TestCase):
    @patch('ml.comprehensive_features.comprehensive_extractor.extract')
    def test_extract_features_delegation(self, mock_extract):
        """Verify extract_features correctly delegates to the singleton extractor"""
        mock_extract.return_value = "mock_array"
        result = extract_features("payload", "path", "query", {"header": "val"})

        mock_extract.assert_called_once_with("payload", "path", "query", {"header": "val"})
        self.assertEqual(result, "mock_array")

if __name__ == '__main__':
    unittest.main()
