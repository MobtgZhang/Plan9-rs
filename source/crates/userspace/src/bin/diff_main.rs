use plan9_userspace::diff::{DiffLineType, diff_strings};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <file1> <file2>", args.get(0).map(|s| s.as_str()).unwrap_or("diff"));
        std::process::exit(2);
    }
    let text1 = std::fs::read_to_string(&args[1]).unwrap_or_default();
    let text2 = std::fs::read_to_string(&args[2]).unwrap_or_default();
    let diff = diff_strings(&text1, &text2);
    for line in &diff {
        match line.line_type {
            DiffLineType::Equal => print!(" {} {}", line.old_line_num.unwrap_or(0), line.content),
            DiffLineType::Insert  => print!(">{} {}", line.new_line_num.unwrap_or(0), line.content),
            DiffLineType::Delete  => print!("<{} {}", line.old_line_num.unwrap_or(0), line.content),
        }
    }
}
