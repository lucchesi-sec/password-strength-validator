#!/usr/bin/env python3
"""
Test suite for the password strength analyzer.
"""

import unittest
import sys
from pathlib import Path

# Add the parent directory to the path to import the analyzer
sys.path.append(str(Path(__file__).parent.parent))
from src.password_analyzer import (
    analyze_password, 
    calculate_entropy, 
    check_complexity, 
    check_patterns,
    load_dictionaries
)


class TestPasswordAnalyzer(unittest.TestCase):
    """Test cases for password analyzer functions."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Load dictionaries for testing
        load_dictionaries()
    
    def test_calculate_entropy(self):
        """Test entropy calculation."""
        # Test basic cases
        self.assertEqual(calculate_entropy(""), 0)
        
        # Test single character class
        entropy = calculate_entropy("abc")
        self.assertGreater(entropy, 0)
        
        # Test multiple character classes
        entropy_mixed = calculate_entropy("Abc123!")
        entropy_simple = calculate_entropy("abcdefg")
        self.assertGreater(entropy_mixed, entropy_simple)
    
    def test_check_complexity(self):
        """Test complexity scoring."""
        # Test very simple password
        score = check_complexity("abc")
        self.assertLess(score, 50)
        
        # Test complex password
        score = check_complexity("ComplexP@ssw0rd123!")
        self.assertGreater(score, 80)
        
        # Test minimum length requirement
        short_score = check_complexity("Abc123!")
        long_score = check_complexity("LongComplexP@ssw0rd123!")
        self.assertGreater(long_score, short_score)
    
    def test_check_patterns(self):
        """Test pattern detection."""
        # Test common password detection
        issues = check_patterns("password")
        self.assertTrue(any("common password" in issue for issue in issues))
        
        # Test sequence detection
        issues = check_patterns("abc123")
        self.assertTrue(any("sequence" in issue for issue in issues))
        
        # Test repeated characters
        issues = check_patterns("aaabbb")
        self.assertTrue(any("repeated characters" in issue for issue in issues))
        
        # Test year detection
        issues = check_patterns("password2023")
        self.assertTrue(any("year" in issue for issue in issues))
    
    def test_analyze_password_weak(self):
        """Test analysis of weak passwords."""
        report = analyze_password("123456")
        
        self.assertEqual(report["password_length"], 6)
        self.assertLess(report["overall_score"], 50)
        self.assertIn("Very Weak", ["Very Weak", "Weak"], report["strength"])
        self.assertGreater(len(report["issues"]), 0)
        self.assertGreater(len(report["recommendations"]), 0)
    
    def test_analyze_password_strong(self):
        """Test analysis of strong passwords."""
        report = analyze_password("MyStr0ng&UnIqueP@ssw0rd2024!")
        
        self.assertGreater(report["password_length"], 12)
        self.assertGreater(report["overall_score"], 60)  # Should be reasonably high
        self.assertGreater(report["entropy_bits"], 50)
        self.assertGreater(report["complexity_score"], 80)
    
    def test_analyze_password_medium(self):
        """Test analysis of medium strength passwords."""
        report = analyze_password("MyPassword123!")
        
        self.assertGreaterEqual(report["password_length"], 8)
        self.assertGreater(report["overall_score"], 25)
        self.assertLess(report["overall_score"], 90)
    
    def test_dictionary_word_detection(self):
        """Test detection of dictionary words."""
        # Test password with dictionary words
        report = analyze_password("password123")
        issues = report["issues"]
        
        # Should detect dictionary word
        self.assertTrue(any("dictionary word" in issue.lower() for issue in issues))
    
    def test_leet_speak_detection(self):
        """Test detection of leet speak substitutions."""
        # Test password with leet speak
        report = analyze_password("p4ssw0rd123")
        issues = report["issues"]
        
        # Should detect leet speak substitution
        self.assertTrue(
            any("leet speak" in issue.lower() or "substitution" in issue.lower() 
                for issue in issues)
        )
    
    def test_report_structure(self):
        """Test that report has required structure."""
        report = analyze_password("TestPassword123!")
        
        # Check required fields
        required_fields = [
            "password_length", "entropy_bits", "complexity_score", 
            "pattern_score", "overall_score", "strength", 
            "issues", "recommendations", "timestamp"
        ]
        
        for field in required_fields:
            self.assertIn(field, report)
        
        # Check data types
        self.assertIsInstance(report["password_length"], int)
        self.assertIsInstance(report["entropy_bits"], (int, float))
        self.assertIsInstance(report["complexity_score"], int)
        self.assertIsInstance(report["pattern_score"], int)
        self.assertIsInstance(report["overall_score"], (int, float))
        self.assertIsInstance(report["strength"], str)
        self.assertIsInstance(report["issues"], list)
        self.assertIsInstance(report["recommendations"], list)
        self.assertIsInstance(report["timestamp"], str)
    
    def test_empty_password(self):
        """Test analysis of empty password."""
        report = analyze_password("")
        
        self.assertEqual(report["password_length"], 0)
        self.assertEqual(report["entropy_bits"], 0)
        self.assertEqual(report["strength"], "Very Weak")
        self.assertGreater(len(report["recommendations"]), 0)


if __name__ == "__main__":
    unittest.main()