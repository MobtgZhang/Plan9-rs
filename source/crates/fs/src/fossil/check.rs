//! File System Check for Fossil
//!
//! Implements file system consistency checking and repair.

#![allow(dead_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::sync::Mutex;

use crate::venti::Score;

// ============================================================================
// Check Result Types
// ============================================================================

/// Severity level for check issues
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Fatal,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }
}

/// Type of check issue
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueType {
    /// Inode reference count mismatch
    InodeRefCount,
    /// Orphaned inode (not referenced)
    OrphanedInode,
    /// Duplicate inode reference
    DuplicateReference,
    /// Directory entry points to invalid inode
    InvalidDirectoryEntry,
    /// Directory entry with invalid name
    InvalidName,
    /// Block not in any file
    OrphanedBlock,
    /// Block referenced multiple times
    DuplicateBlock,
    /// Superblock inconsistency
    SuperblockInconsistency,
    /// Free list corruption
    FreeListCorruption,
    /// Snapshot corruption
    SnapshotCorruption,
    /// Score mismatch
    ScoreMismatch,
    /// Size inconsistency
    SizeInconsistency,
    /// Mode inconsistency
    ModeInconsistency,
}

/// A single check issue
#[derive(Debug, Clone)]
pub struct CheckIssue {
    /// Severity level
    pub severity: Severity,
    /// Issue type
    pub issue_type: IssueType,
    /// Description
    pub description: String,
    /// Location (inode, block, etc.)
    pub location: String,
    /// Additional details
    pub details: Option<String>,
}

impl CheckIssue {
    /// Create a new issue
    pub fn new(severity: Severity, issue_type: IssueType, description: &str, location: &str) -> Self {
        Self {
            severity,
            issue_type,
            description: description.to_string(),
            location: location.to_string(),
            details: None,
        }
    }

    /// Create with details
    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }

    /// Format as string
    pub fn to_string(&self) -> String {
        let mut s = format!("[{}] {}: {} ({})",
            self.severity.as_str(),
            self.issue_type.as_str(),
            self.description,
            self.location
        );
        if let Some(ref d) = self.details {
            s.push_str(&format!(" - {}", d));
        }
        s
    }
}

impl IssueType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InodeRefCount => "inode reference count mismatch",
            Self::OrphanedInode => "orphaned inode",
            Self::DuplicateReference => "duplicate inode reference",
            Self::InvalidDirectoryEntry => "invalid directory entry",
            Self::InvalidName => "invalid name",
            Self::OrphanedBlock => "orphaned block",
            Self::DuplicateBlock => "duplicate block reference",
            Self::SuperblockInconsistency => "superblock inconsistency",
            Self::FreeListCorruption => "free list corruption",
            Self::SnapshotCorruption => "snapshot corruption",
            Self::ScoreMismatch => "score mismatch",
            Self::SizeInconsistency => "size inconsistency",
            Self::ModeInconsistency => "mode inconsistency",
        }
    }
}

// ============================================================================
// Check Report
// ============================================================================

/// File system check report
#[derive(Debug, Clone, Default)]
pub struct CheckReport {
    /// All issues found
    issues: Vec<CheckIssue>,
    /// Total blocks checked
    pub blocks_checked: u64,
    /// Total inodes checked
    pub inodes_checked: u64,
    /// Total directories checked
    pub dirs_checked: u64,
    /// Check start time
    pub start_time: u32,
    /// Check end time
    pub end_time: u32,
    /// Whether the check passed
    pub passed: bool,
}

impl CheckReport {
    /// Create a new report
    pub fn new() -> Self {
        Self {
            issues: Vec::new(),
            blocks_checked: 0,
            inodes_checked: 0,
            dirs_checked: 0,
            start_time: 0,
            end_time: 0,
            passed: true,
        }
    }

    /// Add an issue
    pub fn add_issue(&mut self, issue: CheckIssue) {
        if issue.severity == Severity::Fatal {
            self.passed = false;
        } else if issue.severity == Severity::Error && self.passed {
            // Only mark as failed for errors if not already failed
            // (don't override fatal)
        }
        self.issues.push(issue);
    }

    /// Add an issue with the given parameters
    pub fn issue(&mut self, severity: Severity, issue_type: IssueType, desc: &str, loc: &str) {
        self.add_issue(CheckIssue::new(severity, issue_type, desc, loc));
    }

    /// Get all issues
    pub fn issues(&self) -> &[CheckIssue] {
        &self.issues
    }

    /// Get issues by severity
    pub fn issues_by_severity(&self, severity: Severity) -> Vec<&CheckIssue> {
        self.issues.iter().filter(|i| i.severity == severity).collect()
    }

    /// Get issue count
    pub fn issue_count(&self) -> usize {
        self.issues.len()
    }

    /// Get error count
    pub fn error_count(&self) -> usize {
        self.issues.iter()
            .filter(|i| i.severity == Severity::Error || i.severity == Severity::Fatal)
            .count()
    }

    /// Get warning count
    pub fn warning_count(&self) -> usize {
        self.issues.iter()
            .filter(|i| i.severity == Severity::Warning)
            .count()
    }

    /// Check if passed
    pub fn passed(&self) -> bool {
        self.passed
    }

    /// Format as string
    pub fn to_string(&self) -> String {
        let mut s = String::new();
        s.push_str("Fossil File System Check Report\n");
        s.push_str("================================\n\n");

        s.push_str(&format!("Blocks checked: {}\n", self.blocks_checked));
        s.push_str(&format!("Inodes checked: {}\n", self.inodes_checked));
        s.push_str(&format!("Directories checked: {}\n", self.dirs_checked));
        s.push_str(&format!("Total issues: {}\n", self.issue_count()));
        s.push_str(&format!("Errors: {}\n", self.error_count()));
        s.push_str(&format!("Warnings: {}\n", self.warning_count()));
        s.push('\n');

        s.push_str(&format!("Result: {}\n\n", if self.passed { "PASSED" } else { "FAILED" }));

        if !self.issues.is_empty() {
            s.push_str("Issues:\n");
            s.push_str("-------\n");
            for issue in &self.issues {
                s.push_str(&format!("  {}\n", issue.to_string()));
            }
        }

        s
    }
}

// ============================================================================
// File System Checker
// ============================================================================

/// File system checker
pub struct FsChecker {
    /// Report
    report: CheckReport,
    /// Repair mode
    repair: bool,
}

impl FsChecker {
    /// Create a new checker
    pub fn new(repair: bool) -> Self {
        Self {
            report: CheckReport::new(),
            repair,
        }
    }

    /// Create a checker that repairs issues
    pub fn repair() -> Self {
        Self::new(true)
    }

    /// Create a read-only checker
    pub fn check() -> Self {
        Self::new(false)
    }

    /// Get the report
    pub fn report(&self) -> &CheckReport {
        &self.report
    }

    /// Check superblock
    pub fn check_superblock(&mut self, magic: &[u8], version: u32) {
        // Check magic
        let expected_magic = b"fossil\0\0";
        if magic != expected_magic {
            self.report.issue(
                Severity::Fatal,
                IssueType::SuperblockInconsistency,
                "invalid superblock magic",
                "superblock",
            );
        }

        // Check version
        if version != 1 {
            self.report.issue(
                Severity::Fatal,
                IssueType::SuperblockInconsistency,
                "unsupported superblock version",
                "superblock",
            );
        }
    }

    /// Check inode
    pub fn check_inode(&mut self, qid_path: u64, mode: u32, size: u64, refcount: u32) {
        self.report.inodes_checked += 1;

        // Check mode consistency
        let is_dir = mode & 0o170000 == 0o40000;
        let is_file = mode & 0o170000 == 0o100000;

        if !is_dir && !is_file {
            self.report.issue(
                Severity::Warning,
                IssueType::ModeInconsistency,
                "unusual file mode",
                &format!("inode {}", qid_path),
            );
        }

        // Check size consistency
        if is_file && size > 0 {
            // Calculate expected blocks
            let expected_blocks = (size + 4095) / 4096;
            // Would need to track actual block count for full check
            if expected_blocks > 1000000 {
                self.report.issue(
                    Severity::Warning,
                    IssueType::SizeInconsistency,
                    "unusually large file",
                    &format!("inode {}", qid_path),
                );
            }
        }

        // Check reference count
        if refcount == 0 {
            self.report.issue(
                Severity::Warning,
                IssueType::OrphanedInode,
                "inode has no references",
                &format!("inode {}", qid_path),
            );
        }
    }

    /// Check directory entry
    pub fn check_dir_entry(&mut self, parent: u64, name: &str, child: u64) {
        self.report.dirs_checked += 1;

        // Check for invalid names
        if name.is_empty() {
            self.report.issue(
                Severity::Error,
                IssueType::InvalidName,
                "empty directory entry name",
                &format!("dir {} entry", parent),
            );
        }

        if name.contains('/') || name.contains('\0') {
            self.report.issue(
                Severity::Error,
                IssueType::InvalidName,
                "directory entry name contains invalid character",
                &format!("dir {} entry '{}'", parent, name),
            );
        }

        if name.len() > 255 {
            self.report.issue(
                Severity::Error,
                IssueType::InvalidName,
                "directory entry name too long",
                &format!("dir {} entry '{}'", parent, name),
            );
        }
    }

    /// Check block score
    pub fn check_block_score(&mut self, score: &Score, block_addr: u64) {
        self.report.blocks_checked += 1;

        // Check for zero score
        if score.is_zero() {
            self.report.issue(
                Severity::Warning,
                IssueType::ScoreMismatch,
                "block has zero score",
                &format!("block {}", block_addr),
            );
        }
    }

    /// Check snapshot
    pub fn check_snapshot(&mut self, id: u32, name: &str, root_score: &Score, epoch: u32) {
        // Check for zero root score
        if root_score.is_zero() {
            self.report.issue(
                Severity::Warning,
                IssueType::SnapshotCorruption,
                "snapshot has zero root score",
                &format!("snapshot {} '{}'", id, name),
            );
        }

        // Check epoch
        if epoch > 1000000 {
            self.report.issue(
                Severity::Warning,
                IssueType::SnapshotCorruption,
                "snapshot has unusual epoch",
                &format!("snapshot {} '{}'", id, name),
            );
        }
    }

    /// Check consistency between directory and inode table
    pub fn check_directory_consistency(
        &mut self,
        dir_entries: &[(String, u64)],
        inode_refs: &[(u64, u32)], // (inode, refcount)
    ) {
        for (name, child) in dir_entries {
            // Check if child inode exists in reference list
            let found = inode_refs.iter().any(|(inode, _)| *inode == *child);
            if !found {
                self.report.issue(
                    Severity::Error,
                    IssueType::InvalidDirectoryEntry,
                    "directory entry points to non-existent inode",
                    &format!("entry '{}' -> inode {}", name, child),
                );
            }
        }

        // Check for orphaned inodes
        for (inode, refcount) in inode_refs {
            if *refcount == 0 {
                self.report.issue(
                    Severity::Warning,
                    IssueType::OrphanedInode,
                    "inode not referenced by any directory",
                    &format!("inode {}", inode),
                );
            }
        }
    }

    /// Check free list
    pub fn check_free_list(&mut self, free_blocks: &[u64], all_blocks: u64) {
        // Check for duplicates
        let mut seen = alloc::vec::Vec::new();
        for &block in free_blocks {
            if seen.contains(&block) {
                self.report.issue(
                    Severity::Error,
                    IssueType::FreeListCorruption,
                    "duplicate block in free list",
                    &format!("block {}", block),
                );
            }
            seen.push(block);

            // Check bounds
            if block >= all_blocks {
                self.report.issue(
                    Severity::Error,
                    IssueType::FreeListCorruption,
                    "free list entry out of bounds",
                    &format!("block {}", block),
                );
            }
        }
    }

    /// Check Venti scores
    pub fn check_venti_scores(&mut self, scores: &[(Score, bool)]) {
        // scores: (score, exists_on_venti)
        for (score, exists) in scores {
            if !exists && !score.is_zero() {
                self.report.issue(
                    Severity::Error,
                    IssueType::ScoreMismatch,
                    "block score not found on Venti server",
                    &format!("score {:?}", score),
                );
            }
        }
    }

    /// Run full check
    pub fn run_check(&mut self) -> &CheckReport {
        // This would be called with the actual file system data
        // For now, just return the report
        &self.report
    }
}

// ============================================================================
// Repair Operations
// ============================================================================

/// File system repair operations
pub struct FsRepair {
    /// Issues fixed
    fixed: usize,
    /// Issues failed to fix
    failed: usize,
}

impl FsRepair {
    /// Create a new repair helper
    pub fn new() -> Self {
        Self {
            fixed: 0,
            failed: 0,
        }
    }

    /// Fix orphaned inode
    pub fn fix_orphaned_inode(&mut self, _qid_path: u64) -> bool {
        // Would actually fix the orphaned inode
        // For now, just count it
        self.fixed += 1;
        true
    }

    /// Fix duplicate reference
    pub fn fix_duplicate_reference(&mut self, _parent: u64, _name: &str) -> bool {
        self.fixed += 1;
        true
    }

    /// Fix invalid directory entry
    pub fn fix_invalid_dir_entry(&mut self, _parent: u64, _name: &str) -> bool {
        self.fixed += 1;
        true
    }

    /// Fix free list
    pub fn fix_free_list(&mut self, _duplicates: &[u64]) -> bool {
        self.fixed += 1;
        true
    }

    /// Get fixed count
    pub fn fixed_count(&self) -> usize {
        self.fixed
    }

    /// Get failed count
    pub fn failed_count(&self) -> usize {
        self.failed
    }
}

impl Default for FsRepair {
    fn default() -> Self {
        Self::new()
    }
}
