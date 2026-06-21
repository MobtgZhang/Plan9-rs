//! Copy Files and Directories Command
//!
//! Implementation of the cp command.

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

// ============================================================================
// Constants
// ============================================================================

const BUFFER_SIZE: usize = 8 * 1024;  // 8KB buffer

// ============================================================================
// Options
// ============================================================================

/// Command options
#[derive(Debug, Clone, Default)]
pub struct CpOptions {
    pub force: bool,           // -f: force copy (overwrite)
    pub interactive: bool,     // -i: ask before overwrite
    pub update: bool,          // -u: copy only when source is newer
    pub recursive: bool,       // -r or -R: copy directories recursively
    pub preserve: bool,        // -p: preserve mode, ownership, timestamps
    pub verbose: bool,         // -v: explain what is being done
}

impl CpOptions {
    pub fn parse(args: &[String]) -> (Self, Vec<String>) {
        let mut opts = CpOptions::default();
        let mut paths = Vec::new();
        let mut i = 0;

        while i < args.len() {
            match args[i].as_str() {
                "-f" | "--force" => opts.force = true,
                "-i" | "--interactive" => opts.interactive = true,
                "-u" | "--update" => opts.update = true,
                "-r" | "-R" | "--recursive" => opts.recursive = true,
                "-p" | "--preserve" => opts.preserve = true,
                "-v" | "--verbose" => opts.verbose = true,
                "-n" | "--no-clobber" => opts.force = false,  // -n implies not force
                "--" => {
                    paths.extend_from_slice(&args[i + 1..]);
                    break;
                }
                _ if args[i].starts_with('-') => {
                    let arg = &args[i][1..];
                    for c in arg.chars() {
                        match c {
                            'f' => opts.force = true,
                            'i' => opts.interactive = true,
                            'u' => opts.update = true,
                            'r' | 'R' => opts.recursive = true,
                            'p' => opts.preserve = true,
                            'v' => opts.verbose = true,
                            'n' => opts.force = false,
                            _ => {
                                eprintln!("cp: invalid option -- '{}'", c);
                                return (CpOptions::default(), vec![]);
                            }
                        }
                    }
                }
                _ => {
                    paths.push(args[i].clone());
                }
            }
            i += 1;
        }

        (opts, paths)
    }
}

// ============================================================================
// Implementation
// ============================================================================

/// Copy a single file
fn copy_file(src: &Path, dst: &Path, opts: &CpOptions) -> io::Result<()> {
    // Check if destination exists
    if dst.exists() && !opts.force {
        if !opts.interactive {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "destination already exists",
            ));
        }
    }

    // Open source and destination
    let mut src_file = fs::File::open(src)?;
    let mut dst_file = fs::File::create(dst)?;

    // Copy with buffer
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let bytes_read = src_file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        dst_file.write_all(&buffer[..bytes_read])?;
    }

    if opts.verbose {
        println!("'{}' -> '{}'", src.display(), dst.display());
    }

    Ok(())
}

/// Copy a directory recursively
fn copy_dir(src: &Path, dst: &Path, opts: &CpOptions) -> io::Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir(&src_path, &dst_path, opts)?;
        } else {
            copy_file(&src_path, &dst_path, opts)?;
        }
    }

    Ok(())
}

/// Copy source to destination
fn copy_path(src: &str, dst: &str, opts: &CpOptions) -> io::Result<()> {
    let src_path = Path::new(src);
    let dst_path = Path::new(dst);

    if !src_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("'{}': no such file or directory", src),
        ));
    }

    if src_path.is_dir() {
        if !opts.recursive {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "omitting directory",
            ));
        }

        let final_dst = if !dst_path.exists() {
            dst_path.join(src_path.file_name().unwrap_or_default())
        } else {
            dst_path.to_path_buf()
        };

        copy_dir(src_path, &final_dst, opts)?;
    } else {
        copy_file(src_path, dst_path, opts)?;
    }

    Ok(())
}

/// Run cp command
pub fn run_cp(args: &[String]) -> i32 {
    let (opts, paths) = CpOptions::parse(args);

    if paths.len() < 2 {
        eprintln!("cp: missing file operand");
        eprintln!("Try 'cp --help' for more information.");
        return 1;
    }

    let sources = &paths[..paths.len() - 1];
    let dest = &paths[paths.len() - 1];

    let dest_is_dir = Path::new(dest).is_dir();

    let mut status = 0;

    for src in sources {
        let result = if dest_is_dir {
            let src_path = Path::new(src);
            let dst_path = Path::new(dest).join(src_path.file_name().unwrap_or_default());
            copy_path(src, dst_path.to_str().unwrap_or(src), &opts)
        } else {
            copy_path(src, dest, &opts)
        };

        if let Err(e) = result {
            eprintln!("cp: cannot copy '{}': {}", src, e);
            status = 1;
        }
    }

    status
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_cp(&args[1..]);
    std::process::exit(status);
}
