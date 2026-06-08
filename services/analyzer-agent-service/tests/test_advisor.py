import sys
from unittest.mock import MagicMock

# Mock out external libraries that may not be installed locally
sys.modules['vertexai'] = MagicMock()
sys.modules['vertexai.generative_models'] = MagicMock()
sys.modules['google'] = MagicMock()
sys.modules['google.cloud'] = MagicMock()
sys.modules['google.cloud.bigquery'] = MagicMock()

import unittest
from unittest.mock import patch
import os

# Include parent directory in sys.path so we can import advisor
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from advisor import consult_advisor

class TestAdvisor(unittest.TestCase):
    
    @patch('advisor.GenerativeModel')
    def test_consult_advisor_success(self, mock_gen_model):
        # Mock Response from Gemini
        mock_response = MagicMock()
        mock_response.text = '{"recommended_severity": "critical", "justification": "This is critical because DB port is exposed."}'
        
        mock_model_instance = MagicMock()
        mock_model_instance.generate_content.return_value = mock_response
        mock_gen_model.return_value = mock_model_instance
        
        asset_context = {"asset_id": "test-asset", "hostname": "demo.testfire.net"}
        evidence = {"ports": [3306]}
        
        # Run consultation
        result = consult_advisor(
            asset_context=asset_context,
            evidence=evidence,
            ambiguity_reason="Database port exposed",
            consultation_count=0
        )
        
        self.assertEqual(result.get("recommended_severity"), "critical")
        self.assertTrue(len(result.get("justification", "")) > 0)

    def test_consult_advisor_cap_reached(self):
        # Consultation count >= 3 should return medium severity immediately without model invocation
        result = consult_advisor(
            asset_context={},
            evidence={},
            ambiguity_reason="Any reason",
            consultation_count=3
        )
        
        self.assertEqual(result.get("recommended_severity"), "medium")
        self.assertIn("cap reached", result.get("justification", "").lower())

    @patch('advisor.GenerativeModel')
    def test_consult_advisor_invalid_severity(self, mock_gen_model):
        mock_response = MagicMock()
        mock_response.text = '{"recommended_severity": "super-critical", "justification": "This is invalid."}'
        
        mock_model_instance = MagicMock()
        mock_model_instance.generate_content.return_value = mock_response
        mock_gen_model.return_value = mock_model_instance
        
        # When invalid severity is returned, it should fall back to medium
        result = consult_advisor(
            asset_context={},
            evidence={},
            ambiguity_reason="Any reason",
            consultation_count=0
        )
        self.assertEqual(result.get("recommended_severity"), "medium")
        self.assertIn("failed", result.get("justification", "").lower())

if __name__ == '__main__':
    unittest.main()
