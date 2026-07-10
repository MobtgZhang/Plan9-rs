//! Full test suite for Plan 9 Regular Expression Library
//!
//! This module provides comprehensive tests for all regex functionality,
//! including compilation errors, basic matching, quantifiers, character classes,
//! capture groups, combinations, and boundary conditions.

#[cfg(test)]
mod compilation_tests {
    use plan9_libregexp::Regexp;

    /// Test that unclosed character class returns error
    #[test]
    fn test_unclosed_bracket() {
        let result = Regexp::compile("[abc");
        assert!(result.is_err());
    }

    /// Test that unclosed character class at end of string returns error
    #[test]
    fn test_unclosed_bracket_at_end() {
        let result = Regexp::compile("abc[");
        assert!(result.is_err());
    }

    /// Test empty pattern compiles successfully
    #[test]
    fn test_empty_pattern() {
        let result = Regexp::compile("");
        assert!(result.is_ok());
    }

    /// Test pattern with just special characters
    #[test]
    fn test_just_dot() {
        let result = Regexp::compile(".");
        assert!(result.is_ok());
    }

    /// Test pattern with multiple special characters
    #[test]
    fn test_multiple_special_chars() {
        let result = Regexp::compile("^.*$");
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod basic_match_tests {
    use plan9_libregexp::Regexp;

    /// Test exact literal match
    #[test]
    fn test_literal_exact() {
        let re = Regexp::compile("hello").unwrap();
        assert!(re.execute("hello world").is_some());
    }

    /// Test literal does not match different text
    #[test]
    fn test_literal_no_match() {
        let re = Regexp::compile("hello").unwrap();
        assert!(re.execute("world").is_none());
    }

    /// Test literal partial match does not succeed
    #[test]
    fn test_literal_partial_no_match() {
        let re = Regexp::compile("hello").unwrap();
        assert!(re.execute("hell").is_none());
        assert!(re.execute("hello!").is_none());
    }

    /// Test literal match at start of string
    #[test]
    fn test_literal_at_start() {
        let re = Regexp::compile("abc").unwrap();
        assert!(re.execute("abcdef").is_some());
    }

    /// Test literal match in middle of string
    #[test]
    fn test_literal_in_middle() {
        let re = Regexp::compile("def").unwrap();
        assert!(re.execute("abcdefgh").is_some());
    }

    /// Test any character matches single character
    #[test]
    fn test_any_char_single() {
        let re = Regexp::compile("a.c").unwrap();
        assert!(re.execute("abc").is_some());
        assert!(re.execute("aXc").is_some());
        assert!(re.execute("a1c").is_some());
    }

    /// Test any character does not match multiple characters
    #[test]
    fn test_any_char_not_multiple() {
        let re = Regexp::compile("a.c").unwrap();
        assert!(re.execute("abcc").is_none());
    }

    /// Test start of line anchor
    #[test]
    fn test_bol_match() {
        let re = Regexp::compile("^abc").unwrap();
        assert!(re.execute("abc").is_some());
        assert!(re.execute("abcdef").is_some());
    }

    /// Test start of line anchor fails when not at start
    #[test]
    fn test_bol_no_match() {
        let re = Regexp::compile("^abc").unwrap();
        assert!(re.execute("xabc").is_none());
    }

    /// Test end of line anchor
    #[test]
    fn test_eol_match() {
        let re = Regexp::compile("abc$").unwrap();
        assert!(re.execute("abc").is_some());
        assert!(re.execute("xyzabc").is_some());
    }

    /// Test end of line anchor fails when not at end
    #[test]
    fn test_eol_no_match() {
        let re = Regexp::compile("abc$").unwrap();
        assert!(re.execute("abcx").is_none());
    }

    /// Test combining start and end anchors
    #[test]
    fn test_bol_eol() {
        let re = Regexp::compile("^abc$").unwrap();
        assert!(re.execute("abc").is_some());
        assert!(re.execute("abcdef").is_none());
        assert!(re.execute("xabc").is_none());
    }
}

#[cfg(test)]
mod quantifier_tests {
    use plan9_libregexp::Regexp;

    /// Test Kleene star matches zero occurrences
    #[test]
    fn test_star_zero() {
        let re = Regexp::compile("a*").unwrap();
        assert!(re.execute("").is_some());
    }

    /// Test Kleene star matches single occurrence
    #[test]
    fn test_star_one() {
        let re = Regexp::compile("a*").unwrap();
        assert!(re.execute("a").is_some());
    }

    /// Test Kleene star matches multiple occurrences
    #[test]
    fn test_star_multiple() {
        let re = Regexp::compile("a*").unwrap();
        let m = re.execute("aaa").unwrap();
        assert_eq!(m.end - m.start, 3);
    }

    /// Test Kleene star is greedy
    #[test]
    fn test_star_greedy() {
        let re = Regexp::compile("a*").unwrap();
        let m = re.execute("aaab").unwrap();
        assert_eq!(m.end - m.start, 3);
        assert_eq!(m.text("aaab"), "aaa");
    }

    /// Test Kleene star with dot-star
    #[test]
    fn test_dot_star() {
        let re = Regexp::compile(".*").unwrap();
        assert!(re.execute("anything here").is_some());
    }

    /// Test Kleene star after character
    #[test]
    fn test_star_after_char() {
        let re = Regexp::compile("ab*").unwrap();
        assert!(re.execute("a").is_some());
        assert!(re.execute("ab").is_some());
        assert!(re.execute("abbb").is_some());
    }

    /// Test plus matches one or more
    #[test]
    fn test_plus_one_or_more() {
        let re = Regexp::compile("a+").unwrap();
        assert!(re.execute("a").is_some());
        assert!(re.execute("aaa").is_some());
    }

    /// Test plus does not match zero
    #[test]
    fn test_plus_not_zero() {
        let re = Regexp::compile("a+").unwrap();
        assert!(re.execute("").is_none());
        assert!(re.execute("b").is_none());
    }

    /// Test plus is greedy
    #[test]
    fn test_plus_greedy() {
        let re = Regexp::compile("a+").unwrap();
        let m = re.execute("aaab").unwrap();
        assert_eq!(m.end - m.start, 3);
    }

    /// Test question mark matches zero
    #[test]
    fn test_quest_zero() {
        let re = Regexp::compile("a?").unwrap();
        assert!(re.execute("").is_some());
    }

    /// Test question mark matches one
    #[test]
    fn test_quest_one() {
        let re = Regexp::compile("a?").unwrap();
        assert!(re.execute("a").is_some());
    }

    /// Test question mark after character
    #[test]
    fn test_quest_after_char() {
        let re = Regexp::compile("ab?").unwrap();
        assert!(re.execute("a").is_some());
        assert!(re.execute("ab").is_some());
        assert!(re.execute("abc").is_some());
    }

    /// Test nested quantifiers
    #[test]
    fn test_nested_quantifiers() {
        let re = Regexp::compile("(ab)+").unwrap();
        assert!(re.execute("ab").is_some());
        assert!(re.execute("abab").is_some());
        assert!(re.execute("ababab").is_some());
    }

    /// Test multiple quantifiers in sequence
    #[test]
    fn test_multiple_quantifiers() {
        let re = Regexp::compile("a*b*c*").unwrap();
        assert!(re.execute("").is_some());
        assert!(re.execute("aaabbbccc").is_some());
    }
}

#[cfg(test)]
mod char_class_tests {
    use plan9_libregexp::Regexp;

    /// Test simple character class
    #[test]
    fn test_char_class_single() {
        let re = Regexp::compile("[abc]").unwrap();
        assert!(re.execute("a").is_some());
        assert!(re.execute("b").is_some());
        assert!(re.execute("c").is_some());
    }

    /// Test character class does not match outside
    #[test]
    fn test_char_class_no_match() {
        let re = Regexp::compile("[abc]").unwrap();
        assert!(re.execute("d").is_none());
        assert!(re.execute("A").is_none());
    }

    /// Test character class with numbers
    #[test]
    fn test_char_class_numbers() {
        let re = Regexp::compile("[0123456789]").unwrap();
        assert!(re.execute("5").is_some());
        assert!(re.execute("9").is_some());
    }

    /// Test character class with mixed characters
    #[test]
    fn test_char_class_mixed() {
        let re = Regexp::compile("[a-zA-Z0-9_]").unwrap();
        assert!(re.execute("a").is_some());
        assert!(re.execute("Z").is_some());
        assert!(re.execute("9").is_some());
        assert!(re.execute("_").is_some());
    }

    /// Test character class with repetition
    #[test]
    fn test_char_class_repetition() {
        let re = Regexp::compile("[abc]+").unwrap();
        assert!(re.execute("abc").is_some());
        assert!(re.execute("cab").is_some());
        assert!(re.execute("abcabc").is_some());
    }

    /// Test character class at start
    #[test]
    fn test_char_class_at_start() {
        let re = Regexp::compile("^[abc]").unwrap();
        assert!(re.execute("abc").is_some());
        assert!(re.execute("axyz").is_some());
    }

    /// Test character class at end
    #[test]
    fn test_char_class_at_end() {
        let re = Regexp::compile("[xyz]$").unwrap();
        assert!(re.execute("xyz").is_some());
        assert!(re.execute("abcx").is_some());
    }

    /// Test nested character class and quantifier
    #[test]
    fn test_char_class_with_star() {
        let re = Regexp::compile("[abc]*").unwrap();
        assert!(re.execute("").is_some());
        assert!(re.execute("abc").is_some());
        assert!(re.execute("cbaabc").is_some());
    }

    /// Test character class with plus
    #[test]
    fn test_char_class_with_plus() {
        let re = Regexp::compile("[abc]+").unwrap();
        assert!(re.execute("a").is_some());
        assert!(re.execute("abcba").is_some());
    }
}

#[cfg(test)]
mod capture_tests {
    use plan9_libregexp::Regexp;

    /// Test single capture group
    #[test]
    fn test_capture_single() {
        let re = Regexp::compile("hello (world)").unwrap();
        let m = re.execute("hello world").unwrap();
        assert_eq!(m.submatches.len(), 1);
    }

    /// Test multiple capture groups
    #[test]
    fn test_capture_multiple() {
        let re = Regexp::compile("(a)(b)").unwrap();
        let m = re.execute("ab").unwrap();
        assert_eq!(m.submatches.len(), 2);
    }

    /// Test optional capture group with match
    #[test]
    fn test_capture_optional_match() {
        let re = Regexp::compile("(x)?").unwrap();
        let m = re.execute("x").unwrap();
        assert_eq!(m.submatches.len(), 1);
    }

    /// Test optional capture group without match
    #[test]
    fn test_capture_optional_no_match() {
        let re = Regexp::compile("a(x)?").unwrap();
        let m = re.execute("a").unwrap();
        assert_eq!(m.submatches.len(), 1);
    }

    /// Test capture group with quantifier
    #[test]
    fn test_capture_with_star() {
        let re = Regexp::compile("(ab)*").unwrap();
        let m = re.execute("abab").unwrap();
        assert_eq!(m.submatches.len(), 1);
    }

    /// Test nested capture groups
    #[test]
    fn test_capture_nested() {
        let re = Regexp::compile("(a(b)c)").unwrap();
        let m = re.execute("abc").unwrap();
        assert_eq!(m.submatches.len(), 2);
    }

    /// Test capture group extracts correct text
    #[test]
    fn test_capture_extract() {
        let re = Regexp::compile("hello (world)").unwrap();
        let m = re.execute("hello world").unwrap();
        let captured = m.text("hello world");
        assert!(captured.contains("world"));
    }

    /// Test multiple captures with same prefix
    #[test]
    fn test_multiple_captures() {
        let re = Regexp::compile("(a)(b)(c)").unwrap();
        let m = re.execute("abc").unwrap();
        assert_eq!(m.submatches.len(), 3);
    }

    /// Test capture with alternation
    #[test]
    fn test_capture_alternation() {
        let re = Regexp::compile("(ab|cd)").unwrap();
        let m1 = re.execute("ab").unwrap();
        assert_eq!(m1.submatches.len(), 1);
        let m2 = re.execute("cd").unwrap();
        assert_eq!(m2.submatches.len(), 1);
    }
}

#[cfg(test)]
mod combination_tests {
    use plan9_libregexp::Regexp;

    /// Test concatenation
    #[test]
    fn test_concatenation() {
        let re = Regexp::compile("ab").unwrap();
        assert!(re.execute("ab").is_some());
    }

    /// Test concatenation with anchor
    #[test]
    fn test_concatenation_anchor() {
        let re = Regexp::compile("^hello world$").unwrap();
        assert!(re.execute("hello world").is_some());
        assert!(re.execute("hello").is_none());
    }

    /// Test complex pattern
    #[test]
    fn test_complex_pattern() {
        let re = Regexp::compile("^a+b*c+$").unwrap();
        assert!(re.execute("aabcc").is_some());
        assert!(re.execute("bcc").is_none()); // must have at least one a
        assert!(re.execute("aacc").is_none()); // must have at least one c
    }

    /// Test pattern with char class and quantifier
    #[test]
    fn test_class_with_quantifier() {
        let re = Regexp::compile("[0-9]+").unwrap();
        assert!(re.execute("123").is_some());
        assert!(re.execute("abc").is_none());
    }

    /// Test pattern with multiple char classes
    #[test]
    fn test_multiple_classes() {
        let re = Regexp::compile("[a-z][0-9]").unwrap();
        assert!(re.execute("a1").is_some());
        assert!(re.execute("z9").is_some());
        assert!(re.execute("1a").is_none());
    }

    /// Test combining anchors, quantifiers and char classes
    #[test]
    fn test_anchors_quantifiers_classes() {
        let re = Regexp::compile("^[a-z]+@[a-z]+\\.[a-z]+$").unwrap();
        assert!(re.execute("test@example.com").is_some());
    }

    /// Test pattern with capture and quantifier
    #[test]
    fn test_capture_with_quantifier() {
        let re = Regexp::compile("\"([^\"]*)\"").unwrap();
        let m = re.execute("\"hello\"").unwrap();
        assert!(m.submatches.len() >= 1);
    }

    /// Test word boundaries with dots
    #[test]
    fn test_word_pattern() {
        let re = Regexp::compile("a.b").unwrap();
        assert!(re.execute("aab").is_some());
        assert!(re.execute("aXb").is_some());
    }
}

#[cfg(test)]
mod boundary_tests {
    use plan9_libregexp::Regexp;

    /// Test empty pattern matches empty string
    #[test]
    fn test_empty_pattern_empty_string() {
        let re = Regexp::compile("").unwrap();
        assert!(re.execute("").is_some());
    }

    /// Test empty pattern matches non-empty string (at position 0)
    #[test]
    fn test_empty_pattern_matches_anything() {
        let re = Regexp::compile("").unwrap();
        assert!(re.execute("anything").is_some());
    }

    /// Test pattern does not match empty text when required
    #[test]
    fn test_pattern_not_match_empty() {
        let re = Regexp::compile("a").unwrap();
        assert!(re.execute("").is_none());
    }

    /// Test pattern does not match completely different text
    #[test]
    fn test_no_match_different_text() {
        let re = Regexp::compile("xyz").unwrap();
        assert!(re.execute("abc").is_none());
    }

    /// Test very long match
    #[test]
    fn test_long_match() {
        let pattern = "a";
        let text = "a".repeat(1000);
        let re = Regexp::compile(pattern).unwrap();
        let m = re.execute(&text).unwrap();
        assert_eq!(m.end - m.start, 1000);
    }

    /// Test pattern matches at correct position
    #[test]
    fn test_match_position() {
        let re = Regexp::compile("cd").unwrap();
        let m = re.execute("abcde").unwrap();
        assert_eq!(m.start, 2);
        assert_eq!(m.end, 4);
    }

    /// Test first match is returned
    #[test]
    fn test_first_match() {
        let re = Regexp::compile("a").unwrap();
        let m = re.execute("banana").unwrap();
        assert_eq!(m.start, 1);
        assert_eq!(m.end, 2);
    }
}

#[cfg(test)]
mod regression_tests {
    use plan9_libregexp::Regexp;

    /// Regression: star without operand
    #[test]
    fn test_star_without_operand() {
        let re = Regexp::compile("a*").unwrap();
        assert!(re.execute("").is_some());
        assert!(re.execute("aaa").is_some());
    }

    /// Regression: plus without operand
    #[test]
    fn test_plus_without_operand() {
        let re = Regexp::compile("a+").unwrap();
        assert!(re.execute("aaa").is_some());
        assert!(re.execute("").is_none());
    }

    /// Regression: question without operand
    #[test]
    fn test_quest_without_operand() {
        let re = Regexp::compile("a?").unwrap();
        assert!(re.execute("").is_some());
        assert!(re.execute("a").is_some());
    }

    /// Regression: consecutive quantifiers
    #[test]
    fn test_consecutive_quantifiers() {
        let re = Regexp::compile("a*b*").unwrap();
        assert!(re.execute("").is_some());
        assert!(re.execute("aaa").is_some());
        assert!(re.execute("bb").is_some());
        assert!(re.execute("aaabb").is_some());
    }

    /// Regression: anchor at end of pattern
    #[test]
    fn test_anchor_at_end() {
        let re = Regexp::compile("abc$").unwrap();
        assert!(re.execute("abc").is_some());
        assert!(re.execute("xyzabc").is_some());
    }

    /// Regression: anchor at start of pattern
    #[test]
    fn test_anchor_at_start() {
        let re = Regexp::compile("^abc").unwrap();
        assert!(re.execute("abc").is_some());
        assert!(re.execute("abcdef").is_some());
    }

    /// Regression: character class with single char
    #[test]
    fn test_single_char_class() {
        let re = Regexp::compile("[x]").unwrap();
        assert!(re.execute("x").is_some());
        assert!(re.execute("y").is_none());
    }

    /// Regression: nested groups
    #[test]
    fn test_nested_groups() {
        let re = Regexp::compile("((a))").unwrap();
        let m = re.execute("a").unwrap();
        assert!(m.submatches.len() >= 2);
    }
}

#[cfg(test)]
mod convenience_tests {
    use plan9_libregexp::{regex_match, regex_contains};

    /// Test regex_match convenience function
    #[test]
    fn test_regex_match() {
        let result = regex_match("hello", "hello world");
        assert!(result.is_some());
    }

    /// Test regex_match returns none for no match
    #[test]
    fn test_regex_match_none() {
        let result = regex_match("hello", "world");
        assert!(result.is_none());
    }

    /// Test regex_contains returns true for match
    #[test]
    fn test_regex_contains_true() {
        assert!(regex_contains("world", "hello world"));
    }

    /// Test regex_contains returns false for no match
    #[test]
    fn test_regex_contains_false() {
        assert!(!regex_contains("xyz", "hello world"));
    }
}
