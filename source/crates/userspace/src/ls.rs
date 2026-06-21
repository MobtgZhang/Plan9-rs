//! List Files Command
//!
//! Implementation of the ls command.

use std::env;
use std::path::Path;
use std::fs;
use std::io;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

// ============================================================================
// Options
// ============================================================================

/// Command line options
#[derive(Debug, Clone, Default)]
pub struct LsOptions {
    pub all: bool,           // -a: show hidden files
    pub long_format: bool,  // -l: long format
    pub recursive: bool,     // -R: recursive
    pub single_column: bool,  // -1: single column
    pub show_inode: bool,    // -i: show inode numbers
    pub show_size: bool,     // -s: show size
}

// ============================================================================
// Entry
// ============================================================================

/// Entry information
#[derive(Debug)]
pub struct EntryInfo {
    pub name: String,
    pub is_dir: bool,
    pub is_link: bool,
    pub size: u64,
    pub mtime: u64,
    pub inode: u64,
}

// ============================================================================
// Main
// ============================================================================

/// Run ls command
pub fn run_ls(args: &[String]) -> i32 {
    let mut opts = LsOptions::default();
    let mut paths = Vec::new();

    for arg in args {
        match arg.as_str() {
            "-a" => opts.all = true,
            "-l" => opts.long_format = true,
            "-R" => opts.recursive = true,
            "-1" => opts.single_column = true,
            "-i" => opts.show_inode = true,
            "-s" => opts.show_size = true,
            _ => paths.push(arg.clone()),
        }
    }

    if paths.is_empty() {
        paths.push(".".to_string());
    }

    let mut status = 0;
    let multiple = paths.len() > 1;

    for path_str in &paths {
        if multiple {
            println!("{}:", path_str);
        }

        match list_dir(path_str, &opts) {
            Ok(entries) => {
                for entry in entries {
                    print_entry(&entry, &opts);
                }
            }
            Err(e) => {
                eprintln!("ls: cannot access '{}': {}", path_str, e);
                status = 1;
            }
        }
    }

    status
}

fn list_dir(path: &str, _opts: &LsOptions) -> io::Result<Vec<EntryInfo>> {
    let mut entries = Vec::new();
    let path = Path::new(path);

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let metadata = entry.metadata()?;

        #[cfg(unix)]
        let (mtime, inode) = {
            let meta = entry.metadata()?;
            (meta.mtime() as u64, meta.ino())
        };
        #[cfg(not(unix))]
        let (mtime, inode) = (0u64, 0u64);

        entries.push(EntryInfo {
            name,
            is_dir: metadata.is_dir(),
            is_link: metadata.file_type().is_symlink(),
            size: metadata.len(),
            mtime,
            inode,
        });
    }

    entries.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    Ok(entries)
}

fn print_entry(entry: &EntryInfo, opts: &LsOptions) {
    if opts.long_format {
        let file_type = if entry.is_dir { 'd' } else { '-' };
        let perms = if entry.is_dir { "rwxr-xr-x" } else { "rw-r--r--" };

        print!("{} {} ", file_type, perms);

        if opts.show_size {
            print!("{:>6} ", entry.size);
        }

        if opts.show_inode {
            print!("{:>8} ", entry.inode);
        }

        println!("{}", entry.name);
    } else {
        println!("{}", entry.name);
    }
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_ls(&args[1..]);
    std::process::exit(status);
}
