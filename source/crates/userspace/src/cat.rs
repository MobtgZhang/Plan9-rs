//! Cat Command Implementation
//!
//! Concatenate files to standard output.

use std::env;
use std::fs;
use std::io::{self, Read};

// ============================================================================
// Options
// ============================================================================

/// Command options
#[derive(Debug, Clone, Default)]
pub struct CatOptions {
    pub number_lines: bool,      // -n: number all lines
    pub squeeze_blank: bool,     // -s: squeeze multiple blank lines
    pub show_ends: bool,        // -E: show line endings
    pub show_tabs: bool,        // -T: show tabs
}

// ============================================================================
// Cat Implementation
// ============================================================================

/// Cat a single file
fn cat_file(path: &str, opts: &CatOptions) -> io::Result<()> {
    let mut file = fs::File::open(path)?;
    let mut prev_blank = false;
    let mut line_num = 0;

    if opts.number_lines || opts.squeeze_blank {
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        for line in content.lines() {
            let is_blank = line.trim().is_empty();

            if opts.squeeze_blank && is_blank && prev_blank {
                continue;
            }

            if opts.number_lines && !is_blank {
                line_num += 1;
                print!("{:6}\t", line_num);
            }

            if opts.show_ends {
                println!("{}$", line);
            } else if opts.show_tabs {
                println!("{}", line.replace('\t', "^I"));
            } else {
                println!("{}", line);
            }

            prev_blank = is_blank;
        }
    } else {
        io::copy(&mut file, &mut io::stdout())?;
    }

    Ok(())
}

/// Run cat command
pub fn run_cat(files: &[String]) -> i32 {
    let opts = CatOptions::default();

    if files.is_empty() {
        // Read from stdin
        io::copy(&mut io::stdin(), &mut io::stdout()).ok();
        return 0;
    }

    let mut status = 0;

    for file in files {
        if let Err(e) = cat_file(file, &opts) {
            eprintln!("cat: {}: {}", file, e);
            status = 1;
        }
    }

    status
}

/// Main entry point
pub fn main() {
    let args: Vec<String> = env::args().collect();
    let status = run_cat(&args[1..]);
    std::process::exit(status);
}
