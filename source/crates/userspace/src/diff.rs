//! diff - Compare files line by line
//!
//! This is a simplified implementation of the POSIX/Plan 9 diff utility.
//! Supports unified (-u) and context (-c) output formats.

use std::cmp::{max, min};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone)]
pub enum DiffLineType {
    Equal,
    Insert,
    Delete,
}

#[derive(Debug, Clone)]
pub struct DiffLine {
    pub line_type: DiffLineType,
    pub content: String,
    pub old_line_num: Option<usize>,
    pub new_line_num: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct DiffChange {
    pub old_start: usize,
    pub old_count: usize,
    pub new_start: usize,
    pub new_count: usize,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone)]
pub struct DiffOptions {
    pub unified: bool,
    pub context: bool,
    pub context_lines: usize,
    pub recursive: bool,
    pub ignore_case: bool,
    pub show_c_function: bool,
}

impl Default for DiffOptions {
    fn default() -> Self {
        DiffOptions {
            unified: false,
            context: false,
            context_lines: 3,
            recursive: false,
            ignore_case: false,
            show_c_function: false,
        }
    }
}

/// Compute the Longest Common Subsequence (LCS) between two sequences of lines
fn compute_lcs(lines1: &[String], lines2: &[String]) -> Vec<Vec<usize>> {
    let m = lines1.len();
    let n = lines2.len();
    
    let mut dp = vec![vec![0; n + 1]; m + 1];
    
    for i in 1..=m {
        for j in 1..=n {
            if lines1[i - 1] == lines2[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1]);
            }
        }
    }
    
    dp
}

/// Backtrack through LCS table to find the edit script
fn backtrack_lcs(dp: &[Vec<usize>], lines1: &[String], lines2: &[String], 
                  i: usize, j: usize, result: &mut Vec<DiffLine>) {
    if i == 0 && j == 0 {
        return;
    }
    
    if i == 0 {
        for k in 0..j {
            result.push(DiffLine {
                line_type: DiffLineType::Insert,
                content: lines2[k].clone(),
                old_line_num: None,
                new_line_num: Some(k + 1),
            });
        }
    } else if j == 0 {
        for k in 0..i {
            result.push(DiffLine {
                line_type: DiffLineType::Delete,
                content: lines1[k].clone(),
                old_line_num: Some(k + 1),
                new_line_num: None,
            });
        }
    } else if lines1[i - 1] == lines2[j - 1] {
        backtrack_lcs(dp, lines1, lines2, i - 1, j - 1, result);
        result.push(DiffLine {
            line_type: DiffLineType::Equal,
            content: lines1[i - 1].clone(),
            old_line_num: Some(i),
            new_line_num: Some(j),
        });
    } else if dp[i - 1][j] >= dp[i][j - 1] {
        backtrack_lcs(dp, lines1, lines2, i - 1, j, result);
        result.push(DiffLine {
            line_type: DiffLineType::Delete,
            content: lines1[i - 1].clone(),
            old_line_num: Some(i),
            new_line_num: None,
        });
    } else {
        backtrack_lcs(dp, lines1, lines2, i, j - 1, result);
        result.push(DiffLine {
            line_type: DiffLineType::Insert,
            content: lines2[j - 1].clone(),
            old_line_num: None,
            new_line_num: Some(j),
        });
    }
}

/// Compare two files and return the diff lines
pub fn diff_files(file1: &Path, file2: &Path, opts: &DiffOptions) -> io::Result<Vec<DiffLine>> {
    let lines1 = read_lines(file1)?;
    let lines2 = read_lines(file2)?;
    
    let dp = compute_lcs(&lines1, &lines2);
    let mut result = Vec::new();
    backtrack_lcs(&dp, &lines1, &lines2, lines1.len(), lines2.len(), &mut result);
    
    Ok(result)
}

/// Read all lines from a file
fn read_lines(path: &Path) -> io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    
    for line in reader.lines() {
        lines.push(line?);
    }
    
    Ok(lines)
}

/// Compare two strings and return diff lines
pub fn diff_strings(text1: &str, text2: &str) -> Vec<DiffLine> {
    let lines1: Vec<String> = text1.lines().map(|s| s.to_string()).collect();
    let lines2: Vec<String> = text2.lines().map(|s| s.to_string()).collect();
    
    let dp = compute_lcs(&lines1, &lines2);
    let mut result = Vec::new();
    backtrack_lcs(&dp, &lines1, &lines2, lines1.len(), lines2.len(), &mut result);
    
    result
}

/// Print unified diff format
pub fn print_unified_diff<W: Write>(output: &mut W, file1: &str, file2: &str, 
                                      changes: &[DiffLine], opts: &DiffOptions) -> io::Result<()> {
    let context = opts.context_lines;
    
    // Group changes with context
    let groups = group_changes(changes, context);
    
    if groups.is_empty() {
        return Ok(());
    }
    
    for group in &groups {
        writeln!(output, "--- a/{}", file1)?;
        writeln!(output, "+++ b/{}", file2)?;
        
        for line in &group.lines {
            match line.line_type {
                DiffLineType::Equal => {
                    writeln!(output, " {}", line.content)?;
                }
                DiffLineType::Delete => {
                    writeln!(output, "-{}", line.content)?;
                }
                DiffLineType::Insert => {
                    writeln!(output, "+{}", line.content)?;
                }
            }
        }
        writeln!(output)?;
    }
    
    Ok(())
}

/// Group consecutive diff lines for context display
fn group_changes(lines: &[DiffLine], context: usize) -> Vec<DiffChange> {
    if lines.is_empty() {
        return Vec::new();
    }
    
    let mut groups = Vec::new();
    let mut current_group: Option<DiffChange> = None;
    let mut equal_run_len = 0;
    
    for line in lines {
        match line.line_type {
            DiffLineType::Equal => {
                equal_run_len += 1;
                
                if let Some(ref mut g) = current_group {
                    if equal_run_len <= context * 2 + 1 {
                        g.lines.push(line.clone());
                    } else if equal_run_len == context * 2 + 1 {
                        g.lines.push(line.clone());
                        groups.push(current_group.take().unwrap());
                        current_group = None;
                    }
                }
            }
            _ => {
                if current_group.is_none() {
                    let start = if lines.len() >= context {
                        lines.iter()
                            .position(|l| l.line_type != DiffLineType::Equal)
                            .unwrap_or(0)
                            .saturating_sub(context)
                    } else {
                        0
                    };
                    
                    current_group = Some(DiffChange {
                        old_start: lines[start].old_line_num.unwrap_or(1),
                        old_count: 0,
                        new_start: lines[start].new_line_num.unwrap_or(1),
                        new_count: 0,
                        lines: Vec::new(),
                    });
                    equal_run_len = 0;
                }
                
                current_group.as_mut().unwrap().lines.push(line.clone());
                equal_run_len = 0;
            }
        }
    }
    
    if let Some(g) = current_group {
        groups.push(g);
    }
    
    groups
}

/// Print context diff format
pub fn print_context_diff<W: Write>(output: &mut W, file1: &str, file2: &str,
                                      changes: &[DiffLine], opts: &DiffOptions) -> io::Result<()> {
    let context = opts.context_lines;
    let groups = group_changes(changes, context);
    
    if groups.is_empty() {
        return Ok(());
    }
    
    for group in &groups {
        let old_end = group.lines.iter()
            .filter_map(|l| l.old_line_num)
            .max()
            .unwrap_or(group.old_start);
        let new_end = group.lines.iter()
            .filter_map(|l| l.new_line_num)
            .max()
            .unwrap_or(group.new_start);
        
        writeln!(output, "*** {} ****", file1)?;
        writeln!(output, "--- {} ----", file2)?;
        
        for line in &group.lines {
            match line.line_type {
                DiffLineType::Equal => {
                    if let (Some(old), Some(new)) = (line.old_line_num, line.new_line_num) {
                        writeln!(output, "  {} {}", old, line.content)?;
                    }
                }
                DiffLineType::Delete => {
                    if let Some(old) = line.old_line_num {
                        writeln!(output, "-{} {}", old, line.content)?;
                    }
                }
                DiffLineType::Insert => {
                    if let Some(new) = line.new_line_num {
                        writeln!(output, "+{} {}", new, line.content)?;
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// Print simple diff format
pub fn print_diff<W: Write>(output: &mut W, changes: &[DiffLine]) -> io::Result<()> {
    for line in changes {
        match line.line_type {
            DiffLineType::Equal => {}
            DiffLineType::Delete => {
                if let Some(n) = line.old_line_num {
                    writeln!(output, "{}d{}", n, line.new_line_num.map(|x| x.to_string()).unwrap_or_default())?;
                }
                writeln!(output, "< {}", line.content)?;
            }
            DiffLineType::Insert => {
                if let Some(n) = line.new_line_num {
                    writeln!(output, "{}a{}", line.old_line_num.map(|x| x.to_string()).unwrap_or_default(), n)?;
                }
                writeln!(output, "> {}", line.content)?;
            }
        }
    }
    Ok(())
}

/// Main diff function that prints diff to stdout
pub fn run_diff(args: &[String]) -> i32 {
    let mut opts = DiffOptions::default();
    let mut files = Vec::new();
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--unified" => opts.unified = true,
            "-c" | "--context" => opts.context = true,
            "-C" | "--context=" => {
                if let Some(n) = args[i].trim_start_matches("-C=").parse::<usize>().ok() {
                    opts.context = true;
                    opts.context_lines = n;
                }
            }
            "-r" | "--recursive" => opts.recursive = true,
            "-i" | "--ignore-case" => opts.ignore_case = true,
            "-q" | "--brief" => {}
            "-" if !args[i].starts_with("--") => {
                if args[i] == "-u" || args[i] == "-c" || args[i] == "-r" || args[i] == "-i" || args[i] == "-q" {
                    // Already handled
                } else {
                    files.push(args[i].clone());
                }
            }
            f => {
                if !f.starts_with('-') {
                    files.push(f.to_string());
                }
            }
        }
        i += 1;
    }
    
    if files.len() < 2 {
        eprintln!("Usage: diff [-u|-c] [-r] file1 file2");
        return 1;
    }
    
    let file1 = Path::new(&files[0]);
    let file2 = Path::new(&files[1]);
    
    let result = match diff_files(file1, file2, &opts) {
        Ok(changes) => {
            if changes.is_empty() {
                0
            } else {
                let has_changes = changes.iter().any(|c| c.line_type != DiffLineType::Equal);
                if !has_changes {
                    0
                } else {
                    let mut stdout = io::stdout();
                    if opts.unified {
                        let _ = print_unified_diff(&mut stdout, &files[0], &files[1], &changes, &opts);
                    } else if opts.context {
                        let _ = print_context_diff(&mut stdout, &files[0], &files[1], &changes, &opts);
                    } else {
                        let _ = print_diff(&mut stdout, &changes);
                    }
                    1
                }
            }
        }
        Err(e) => {
            eprintln!("diff: {}: {}", files[0], e);
            2
        }
    };
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_files() {
        let text = "hello\nworld\n";
        let diff = diff_strings(text, text);
        assert!(diff.iter().all(|l| l.line_type == DiffLineType::Equal));
    }

    #[test]
    fn test_different_files() {
        let text1 = "hello\nworld\n";
        let text2 = "hello\nrust\n";
        let diff = diff_strings(text1, text2);
        
        assert!(diff.iter().any(|l| l.line_type == DiffLineType::Delete));
        assert!(diff.iter().any(|l| l.line_type == DiffLineType::Insert));
    }

    #[test]
    fn test_empty_files() {
        let diff = diff_strings("", "");
        assert!(diff.is_empty());
    }

    #[test]
    fn test_add_lines() {
        let text1 = "hello\n";
        let text2 = "hello\nworld\n";
        let diff = diff_strings(text1, text2);
        assert!(diff.iter().any(|l| l.line_type == DiffLineType::Insert));
    }

    #[test]
    fn test_remove_lines() {
        let text1 = "hello\nworld\n";
        let text2 = "hello\n";
        let diff = diff_strings(text1, text2);
        assert!(diff.iter().any(|l| l.line_type == DiffLineType::Delete));
    }
}
