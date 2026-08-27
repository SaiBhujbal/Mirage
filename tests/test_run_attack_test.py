import unittest
from unittest.mock import MagicMock, patch
import sys

# Create mock objects for the dependencies
mock_action = MagicMock()
mock_action.ALLOW = 0
mock_action.BLOCK = 5

# Define a mock RequestContext that returns its kwargs
def mock_rc_side_effect(**kwargs):
    return kwargs

mock_request_context = MagicMock(side_effect=mock_rc_side_effect)

# Mock sys.modules
mock_modules = {
    'orjson': MagicMock(),
    'pydantic_settings': MagicMock(),
    'pydantic': MagicMock(),
    'core.security_imports': MagicMock(),
    'core.waf_engine': MagicMock(),
    'core.models': MagicMock()
}
mock_modules['core.models'].Action = mock_action
mock_modules['core.models'].RequestContext = mock_request_context

class TestRunAttackTest(unittest.TestCase):
    def setUp(self):
        self.mock_waf = MagicMock()

    @patch.dict(sys.modules, mock_modules)
    def test_run_attack_test_success(self):
        """Test run_attack_test when all attacks are detected and blocked"""
        # We need to import main INSIDE the test or use patch.dict correctly
        if 'main' in sys.modules:
            del sys.modules['main']
        import main
        main.Action = mock_action
        main.RequestContext = mock_request_context

        # Configure mock waf
        mock_result = MagicMock()
        mock_result.detections = [MagicMock()]
        mock_result.action = 5 # Action.BLOCK
        self.mock_waf.analyze_request.return_value = mock_result

        with patch('sys.stdout') as mock_stdout:
            results = main.run_attack_test(waf=self.mock_waf)

        self.assertFalse(results['success'])
        self.assertEqual(results['categories']['SQL Injection']['status'], 'PASS')
        self.assertEqual(results['categories']['Benign (FP Test)']['status'], 'FAIL')

    @patch.dict(sys.modules, mock_modules)
    def test_run_attack_test_failure_on_missed_attacks(self):
        """Test run_attack_test when attacks are NOT detected"""
        if 'main' in sys.modules:
            del sys.modules['main']
        import main
        main.Action = mock_action
        main.RequestContext = mock_request_context

        mock_result = MagicMock()
        mock_result.detections = []
        mock_result.action = 0 # Action.ALLOW
        self.mock_waf.analyze_request.return_value = mock_result

        with patch('sys.stdout') as mock_stdout:
            results = main.run_attack_test(waf=self.mock_waf)

        self.assertFalse(results['success'])
        self.assertEqual(results['categories']['SQL Injection']['status'], 'FAIL')
        self.assertEqual(results['categories']['Benign (FP Test)']['status'], 'PASS')

    @patch.dict(sys.modules, mock_modules)
    def test_run_attack_test_perfect_score(self):
        """Test run_attack_test when attacks are blocked and benign is allowed"""
        if 'main' in sys.modules:
            del sys.modules['main']
        import main
        main.Action = mock_action
        main.RequestContext = mock_request_context

        def analyze_side_effect(ctx):
            client_ip = ctx.get('client_ip', '') if isinstance(ctx, dict) else ''
            res = MagicMock()
            if client_ip.startswith('203.0'):
                res.detections = [MagicMock()]
                res.action = 5 # BLOCK
            else:
                res.detections = []
                res.action = 0 # ALLOW
            return res

        self.mock_waf.analyze_request.side_effect = analyze_side_effect

        with patch('sys.stdout') as mock_stdout:
            results = main.run_attack_test(waf=self.mock_waf)

        self.assertTrue(results['success'])
        for cat, data in results['categories'].items():
            self.assertEqual(data['status'], 'PASS', f"Category {cat} should have PASSED")

if __name__ == '__main__':
    unittest.main()
