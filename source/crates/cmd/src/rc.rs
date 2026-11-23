use alloc::{collections::BTreeMap, format, rc::Rc, string::String, vec, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};

use cmd::{env, lineedit, syscall};

#[path = "rc/syntax.rs"]
mod syntax;
use syntax::{Command, Error, Expansion, FileMode, Function, Redirect, Word};

const DEFAULT_PATH: &[u8] = b".\0/bin\0";
const SOURCE_LIMIT: usize = 24 * 1024;
const BUILTINS: &[&str] = &[".", "builtin", "cd", "eval", "exec", "exit", "flag", "help", "rfork", "shift", "wait", "whatis"];
const FLAGS: &[u8] = b"deiIlprsvxcm";
const NOTES: &[(&[u8], &str)] = &[
    (b"hangup", "sighup"),
    (b"interrupt", "sigint"),
    (b"quit", "sigquit"),
    (b"alarm", "sigalrm"),
    (b"kill", "sigkill"),
    (b"sys: fp: ", "sigfpe"),
    (b"term", "sigterm"),
];
static ENABLED_NOTES: AtomicU32 = AtomicU32::new(0);
static PENDING_NOTES: AtomicU32 = AtomicU32::new(0);

extern "C" fn handle_note(_registers: *mut u8, message: *const u8) {
    for (index, (prefix, _)) in NOTES.iter().enumerate() {
        if ENABLED_NOTES.load(Ordering::Relaxed) & (1 << index) == 0 {
            continue;
        }
        if prefix.iter().enumerate().all(|(offset, byte)| unsafe { message.add(offset).read() } == *byte) {
            if PENDING_NOTES.try_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
                (pending >> 28 == 0).then(|| (pending << 4) | (index as u32 + 1))
            }).is_ok() {
                syscall::noted(0);
            }
            break;
        }
    }
    syscall::noted(1);
    syscall::exit(1);
}

const COMMANDS: &[&str] = &[
    "basename", "bind", "cat", "chmod", "chown", "clear", "cmp", "cp", "cut", "date",
    "dc", "diff", "dirname", "du", "echo", "ed", "env", "expr", "false", "fortune",
    "grep", "group", "head", "hostname", "id", "ipconfig", "kill", "ln", "ls",
    "mkdir", "more", "mount", "mv", "netcat", "nl", "passwd", "ping", "printf", "ps", "pwd",
    "rc", "rm", "rmdir", "seq", "sleep", "snap", "snoopy", "sort", "stat", "su", "tail", "tee",
    "test", "time", "touch", "tr", "traceroute", "true", "tty", "uname", "uniq", "units",
    "unmount", "uptime", "useradd", "usermod", "wc", "who", "whoami", "yes",
];

type Result<T> = core::result::Result<T, &'static str>;

fn succeeded(status: &str) -> bool {
    status.bytes().all(|byte| matches!(byte, b'0' | b'|'))
}

#[derive(Clone)]
struct Value {
    text: String,
    meta: Vec<bool>,
}

impl Value {
    fn new(text: String, quoted: bool) -> Self {
        let meta = text.bytes().map(|byte| !quoted && b"*?[".contains(&byte)).collect();
        Self { text, meta }
    }

    fn literal(text: impl Into<String>) -> Self {
        Self::new(text.into(), true)
    }

    fn concat(mut self, other: &Self) -> Self {
        self.text.push_str(&other.text);
        self.meta.extend(&other.meta);
        self
    }
}

#[derive(Default)]
struct Shell {
    functions: BTreeMap<String, Rc<Function>>,
    args: Vec<String>,
    zero: String,
    status: String,
    condition: Option<bool>,
    jobs: Vec<i32>,
    last_job: Option<i32>,
    pipe_files: Vec<i64>,
    handling_notes: bool,
    exiting: bool,
    depth: usize,
    flags: u32,
    tested: usize,
}

impl Shell {
    fn flag(&self, flag: u8) -> bool {
        FLAGS.iter().position(|option| *option == flag).is_some_and(|bit| self.flags & (1 << bit) != 0)
    }

    fn set_flag(&mut self, flag: u8, enabled: bool) -> Result<()> {
        let bit = FLAGS.iter().position(|option| *option == flag).ok_or("unknown shell flag")?;
        if enabled {
            self.flags |= 1 << bit;
        } else {
            self.flags &= !(1 << bit);
        }
        Ok(())
    }

    fn test(&mut self, condition: &Command) -> String {
        self.tested += 1;
        let result = self.execute(condition);
        self.tested -= 1;
        result
    }

    fn execute(&mut self, command: &Command) -> String {
        if self.depth >= 64 {
            return String::from("recursion limit");
        }
        self.depth += 1;
        self.dispatch_notes();
        let pipe_scope = self.pipe_files.len();
        let status = match self.run(command) {
            Ok(status) => status,
            Err(error) => {
                report(error);
                String::from(error)
            }
        };
        for fd in self.pipe_files.drain(pipe_scope..) {
            syscall::close(fd);
        }
        self.depth -= 1;
        self.status.clone_from(&status);
        if self.flag(b'e') && self.tested == 0
            && matches!(command, Command::Simple(_) | Command::Match(..) | Command::Subshell(_))
            && !succeeded(&status)
        {
            syscall::exits(&self.exit_status(status));
        }
        status
    }

    fn dispatch_notes(&mut self) {
        if self.handling_notes {
            return;
        }
        let pending = PENDING_NOTES.swap(0, Ordering::Relaxed);
        if pending == 0 {
            return;
        }
        self.handling_notes = true;
        let status = self.status.clone();
        let condition = self.condition;
        for shift in (0..32).step_by(4).rev() {
            let note = ((pending >> shift) & 15) as usize;
            if note > 0 {
                let name = NOTES[note - 1].1;
                if let Some(body) = self.functions.get(name).cloned() {
                    self.execute(&body.body);
                }
            }
        }
        self.status = status;
        self.condition = condition;
        self.handling_notes = false;
    }

    fn exit_status(&mut self, status: String) -> String {
        if !core::mem::replace(&mut self.exiting, true) {
            if let Some(body) = self.functions.get("sigexit").cloned() {
                self.status = status;
                return self.execute(&body.body);
            }
        }
        status
    }

    fn run(&mut self, command: &Command) -> Result<String> {
        match command {
            Command::Sequence(commands) => {
                let mut status = self.status.clone();
                for command in commands {
                    if !matches!(command, Command::Otherwise(_)) {
                        self.condition = None;
                    }
                    status = self.execute(command);
                    if !matches!(command, Command::If(..)) {
                        self.condition = None;
                    }
                }
                Ok(status)
            }
            Command::Conditional(on_success, left, right) => {
                let status = self.test(left);
                Ok(if succeeded(&status) == *on_success { self.execute(right) } else { status })
            }
            Command::Negate(body) => Ok(if succeeded(&self.execute(body)) { String::from("false") } else { String::new() }),
            Command::If(condition, body) => {
                let status = self.test(condition);
                let matched = succeeded(&status);
                let result = if matched { self.execute(body) } else { status };
                self.condition = Some(matched);
                Ok(result)
            }
            Command::Otherwise(body) => match self.condition.take() {
                Some(false) => Ok(self.execute(body)),
                Some(true) => Ok(self.status.clone()),
                None => Err("if not without if"),
            },
            Command::While(condition, body) => {
                loop {
                    let status = self.test(condition);
                    if !succeeded(&status) {
                        break Ok(status);
                    }
                    self.execute(body);
                    syscall::yield_cpu();
                }
            }
            Command::For(name, words, body) => {
                let values = if let Some(words) = words { self.arguments(words)? } else { self.args.clone() };
                let name = self.variable_name(name)?;
                let old = self.save_variable(&name);
                let result = (|| {
                    let mut status = self.status.clone();
                    for value in values {
                        self.set(&name, &[value])?;
                        status = self.execute(body);
                        syscall::yield_cpu();
                    }
                    Ok(status)
                })();
                self.restore_variable(&name, old);
                result
            }
            Command::Switch(subject, cases) => {
                let text = self.match_subject(subject)?;
                for case in cases {
                    if self.expand_words(&case.patterns)?.iter().any(|pattern| matches(pattern, &text)) {
                        return Ok(self.execute(&case.body));
                    }
                }
                Ok(self.status.clone())
            }
            Command::Match(subject, patterns) => {
                let patterns = self.expand_words(patterns)?;
                let text = self.match_subject(subject)?;
                Ok(if patterns.iter().any(|pattern| matches(pattern, &text)) { String::new() } else { String::from("no match") })
            }
            Command::Function(names, body) => {
                for name in self.arguments(names)? {
                    let value = body.as_ref().map(|function| {
                        format!("fn {} {{{}}}\n", quote(&name), function.source)
                    });
                    if !env::set_value(&format!("fn#{name}"), value.as_deref().unwrap_or("").as_bytes()) {
                        return Err("cannot export function");
                    }
                    self.define(name, body.clone());
                }
                Ok(self.status.clone())
            }
            Command::Simple(words) => {
                let values = self.arguments(words)?;
                self.simple(&values, false)
            }
            Command::Assigned(pairs, body) => self.assign(pairs, body),
            Command::Redirected(redirections, body) => {
                let mut restore = Vec::new();
                let mut writers = Vec::new();
                let result = self.redirect(redirections, &mut restore, &mut writers).map(|()| {
                    if matches!(body.as_ref(), Command::Simple(words) if words.is_empty()) {
                        self.status.clone()
                    } else {
                        self.execute(body)
                    }
                });
                for (target, original) in restore.into_iter().rev() {
                    restore_descriptor(target, original);
                }
                for writer in writers {
                    self.wait(writer);
                }
                result
            }
            Command::Pipe(output, input, left, right) => self.pipeline(*output, *input, left, right),
            Command::Subshell(body) | Command::Background(body) => {
                let background = matches!(command, Command::Background(_));
                let pid = spawn(2 | if background { 8 } else { 0 })?;
                if pid == 0 {
                    self.jobs.clear();
                    if background {
                        let fd = cmd::open_read("/dev/null");
                        if fd >= 0 && fd != 0 {
                            syscall::dup2(fd, 0);
                            syscall::close(fd);
                        }
                    }
                    syscall::exits(&self.execute(body));
                }
                if background {
                    self.last_job = Some(pid);
                    self.jobs.push(pid);
                    syscall::yield_cpu();
                    Ok(self.status.clone())
                } else {
                    Ok(self.wait(pid))
                }
            }
        }
    }

    fn define(&mut self, name: String, body: Option<Rc<Function>>) {
        if let Some(index) = NOTES.iter().position(|(_, signal)| *signal == name) {
            if body.is_some() {
                ENABLED_NOTES.fetch_or(1 << index, Ordering::Relaxed);
            } else {
                ENABLED_NOTES.fetch_and(!(1 << index), Ordering::Relaxed);
            }
        }
        if let Some(body) = body {
            self.functions.insert(name, body);
        } else {
            self.functions.remove(&name);
        }
    }

    fn import_functions(&mut self) {
        let directory = cmd::open_read("/env");
        if directory < 0 {
            return;
        }
        let mut reader = cmd::DirReader::new(directory);
        while let Some(entry) = reader.next_name() {
            let Ok(entry) = core::str::from_utf8(entry) else { continue };
            let Some(name) = entry.strip_prefix("fn#") else { continue };
            if name == "sigexit" {
                continue;
            }
            let fd = cmd::open_read(&format!("/env/{entry}"));
            if fd < 0 {
                continue;
            }
            let source = read_all(fd, SOURCE_LIMIT);
            syscall::close(fd);
            let Ok(Command::Sequence(commands)) = source.and_then(|source| {
                syntax::parse(&source, false).map_err(|_| "invalid environment function")
            }) else { continue };
            if let [Command::Function(names, Some(body))] = commands.as_slice() {
                if matches!(names.as_slice(), [Word::Literal(literal, _)] if literal == name) {
                    self.define(String::from(name), Some(body.clone()));
                }
            }
        }
        syscall::close(directory);
    }

    fn set(&mut self, name: &str, words: &[String]) -> Result<()> {
        if name == "*" {
            self.args = words.to_vec();
        } else if !env::set_value(name, &encode_words(words)) {
            return Err("cannot set environment variable");
        }
        Ok(())
    }

    fn variable(&self, name: &str) -> Vec<String> {
        match name {
            "*" => self.args.clone(),
            "0" => vec![self.zero.clone()],
            "pid" => vec![syscall::getpid().to_string()],
            "apid" => self.last_job.iter().map(ToString::to_string).collect(),
            "status" => vec![self.status.clone()],
            name => {
                if let Ok(position) = name.parse::<usize>() {
                    return self.args.get(position.saturating_sub(1)).cloned().into_iter().collect();
                }
                read_env(name).unwrap_or_default()
            }
        }
    }

    fn expand(&mut self, word: &Word) -> Result<Vec<Value>> {
        match word {
            Word::Literal(text, quoted) => Ok(vec![Value::new(text.clone(), *quoted)]),
            Word::List(words) => self.expand_words(words),
            Word::Variable(name, style, indices) => {
                self.expand_variable(name, *style, indices.as_deref())
            }
            Word::Indirect(word, style, indices) => {
                let mut names = self.expand(word)?;
                if names.len() != 1 {
                    return Err("variable name not singleton");
                }
                let name = names.pop().unwrap();
                self.expand_variable(&name.text, *style, indices.as_deref())
            }
            Word::Concat(left, right) => {
                let right = self.expand(right)?;
                let left = self.expand(left)?;
                let count = left.len().max(right.len());
                if left.is_empty() != right.is_empty() {
                    return Err("null list in concatenation");
                }
                if count == 0 {
                    return Ok(Vec::new());
                }
                if left.len() != right.len() && left.len() != 1 && right.len() != 1 {
                    return Err("mismatched lists in concatenation");
                }
                Ok((0..count).map(|index| left[index % left.len()].clone().concat(&right[index % right.len()])).collect())
            }
            Word::Substitute(separators, body) => {
                let separators = match separators {
                    Some(word) => self.arguments(core::slice::from_ref(word.as_ref()))?,
                    None => read_env("ifs").unwrap_or_else(|| vec![String::from(" \t\n")]),
                };
                let separators = separators.first().map_or("", String::as_str);
                let text = self.capture(body)?;
                Ok(text.split(|character| separators.contains(character)).filter(|field| !field.is_empty())
                    .map(Value::literal).collect())
            }
            Word::PipeFile(read, body) => self.pipe_file(*read, body),
        }
    }

    fn expand_variable(&mut self, name: &str, style: Expansion, indices: Option<&[Word]>) -> Result<Vec<Value>> {
        let values = self.variable(name);
        let Some(indices) = indices else { return Ok(expand_values(values, style)) };
        let mut selected = Vec::new();
        for value in self.expand_words(indices)? {
            let (start, suffix) = decimal_prefix(&value.text);
            let Some(first) = start.checked_sub(1) else { continue };
            let end = match suffix.strip_prefix('-') {
                Some("") => values.len(),
                Some(end) => decimal_prefix(end).0,
                None => start,
            };
            if let Some(range) = values.get(first..end.min(values.len())) {
                selected.extend_from_slice(range);
            }
        }
        Ok(expand_values(selected, style))
    }

    fn expand_words(&mut self, words: &[Word]) -> Result<Vec<Value>> {
        let mut values = Vec::new();
        for word in words.iter().rev() {
            values.extend(self.expand(word)?.into_iter().rev());
        }
        values.reverse();
        Ok(values)
    }

    fn arguments(&mut self, words: &[Word]) -> Result<Vec<String>> {
        Ok(self.expand_words(words)?.into_iter().flat_map(glob).collect())
    }

    fn single(&mut self, word: &Word) -> Result<String> {
        let mut arguments = self.arguments(core::slice::from_ref(word))?;
        if arguments.len() != 1 {
            return Err("expected one word");
        }
        Ok(arguments.pop().unwrap())
    }

    fn variable_name(&mut self, word: &Word) -> Result<String> {
        let mut names = self.expand(word)?;
        if names.len() != 1 {
            return Err("variable name not singleton");
        }
        Ok(names.pop().unwrap().text)
    }

    fn save_variable(&self, name: &str) -> Option<Vec<String>> {
        if name == "*" { Some(self.args.clone()) } else { read_env(name) }
    }

    fn restore_variable(&mut self, name: &str, old: Option<Vec<String>>) {
        if let Some(old) = old {
            let _ = self.set(name, &old);
        } else {
            let path = format!("/env/{name}\0");
            syscall::remove(path.as_ptr());
        }
    }

    fn match_subject(&mut self, word: &Word) -> Result<String> {
        let values: Vec<_> = self.expand(word)?.into_iter().map(|value| value.text).collect();
        Ok(values.join(" "))
    }

    fn assign(&mut self, pairs: &[(Word, Word)], body: &Command) -> Result<String> {
        let persistent = matches!(body, Command::Simple(words) if words.is_empty());
        let mut restore = Vec::new();
        let result = (|| {
            for (name, value) in pairs {
                let name = self.variable_name(name)?;
                let values = self.arguments(core::slice::from_ref(value))?;
                if !persistent {
                    restore.push((name.clone(), self.save_variable(&name)));
                }
                self.set(&name, &values)?;
            }
            Ok(if persistent { self.status.clone() } else { self.execute(body) })
        })();
        for (name, old) in restore.into_iter().rev() {
            self.restore_variable(&name, old);
        }
        result
    }

    fn simple(&mut self, mut words: &[String], mut builtin: bool) -> Result<String> {
        if self.flag(b'x') && !words.is_empty() {
            let command = words.iter().map(|word| quote(word)).collect::<Vec<_>>().join(" ");
            syscall::write_all(2, format!("{command}\n").as_bytes());
        }
        while words.first().is_some_and(|word| word == "builtin")
            && (builtin || !self.functions.contains_key("builtin"))
        {
            builtin = true;
            words = &words[1..];
        }
        let Some(program) = words.first() else { return Ok(String::new()) };
        let args = &words[1..];
        if let Some(body) = self.functions.get(program).filter(|_| !builtin).cloned() {
            let old = core::mem::replace(&mut self.args, args.to_vec());
            let status = self.execute(&body.body);
            self.args = old;
            return Ok(status);
        }
        match program.as_str() {
            "." => {
                let script = args.first().ok_or("usage: . file [args]")?;
                let old = core::mem::replace(&mut self.args, args[1..].to_vec());
                let result = self.source(script, false);
                self.args = old;
                result
            }
            "cd" => {
                let destination = args.first().cloned().or_else(|| self.variable("home").into_iter().next()).ok_or("no home directory")?;
                let path = c_string(destination)?;
                if syscall::chdir(path.as_ptr()) < 0 { Err("can't cd") } else { Ok(String::new()) }
            }
            "exit" => syscall::exits(&self.exit_status(args.first().unwrap_or(&self.status).clone())),
            "shift" => {
                let count = args.first().map_or(Ok(1), |value| value.parse::<usize>()).map_err(|_| "invalid shift count")?;
                if count > self.args.len() {
                    return Err("shift exceeds argument count");
                }
                self.args.drain(..count);
                Ok(String::new())
            }
            "flag" => match args {
                [flag] if flag.len() == 1 && FLAGS.contains(&flag.as_bytes()[0]) => {
                    Ok(if self.flag(flag.as_bytes()[0]) { String::new() } else { String::from("flag not set") })
                }
                [flag, option] if flag.len() == 1 && matches!(option.as_str(), "+" | "-") => {
                    self.set_flag(flag.as_bytes()[0], option == "+")?;
                    Ok(String::new())
                }
                _ => Err("usage: flag f [+-]"),
            },
            "whatis" => Ok(self.whatis(args)),
            "wait" => {
                let mut status = String::new();
                if args.is_empty() {
                    for pid in core::mem::take(&mut self.jobs) {
                        status = self.wait(pid);
                    }
                } else {
                    for arg in args {
                        let pid = arg.parse().map_err(|_| "invalid process id")?;
                        status = self.wait(pid);
                        self.jobs.retain(|job| *job != pid);
                    }
                }
                Ok(status)
            }
            "rfork" => {
                let options = match args {
                    [] => "nes",
                    [options] => options,
                    _ => return Err("usage: rfork [fnesFNEm]"),
                };
                let mut flags = 0;
                for option in options.bytes() {
                    flags |= match option {
                        b'e' => syscall::RFENVG,
                        b'E' => syscall::RFCENVG,
                        b'n' => 1,
                        b'N' => syscall::RFCNAMEG,
                        b's' => syscall::RFNOTEG,
                        b'f' => syscall::RFFDG,
                        b'F' => syscall::RFCFDG,
                        b'm' => syscall::RFNOMNT,
                        _ => return Err("unsupported rfork flag"),
                    };
                }
                if syscall::rfork(flags) < 0 { Err("rfork failed") } else { Ok(String::new()) }
            }
            "eval" => self.evaluate(&args.join(" ")),
            "exec" if !args.is_empty() => exec(args),
            "exec" => Ok(String::new()),
            "help" => {
                help();
                Ok(String::new())
            }
            _ => {
                let pid = spawn(0)?;
                if pid == 0 {
                    let result = exec(words);
                    let error = result.unwrap_err();
                    report(&format!("{program}: {error}"));
                    syscall::exits(error);
                }
                Ok(self.wait(pid))
            }
        }
    }

    fn whatis(&self, names: &[String]) -> String {
        let mut failure = String::new();
        for name in names {
            let values = match name.as_str() {
                "*" | "0" | "pid" | "apid" | "status" => Some(self.variable(name)),
                _ => read_env(name),
            };
            let function = self.functions.get(name);
            if let Some(values) = &values {
                cmd::outln(&format!("{}=({})", quote(name), values.iter().map(|value| quote(value)).collect::<Vec<_>>().join(" ")));
            }
            if let Some(function) = function {
                cmd::outln(&format!("fn {} {{{}}}", quote(name), function.source));
            } else if values.is_none() {
                if BUILTINS.contains(&name.as_str()) {
                    cmd::outln(&format!("builtin {}", quote(name)));
                } else if let Some(path) = command_paths(name).into_iter().find(|path| {
                    let mut stat = [0; 320];
                    cmd::stat_text(path, &mut stat).and_then(|count| {
                        core::str::from_utf8(&stat[..count]).ok()?.trim_end().rsplit(' ').nth(2)?.parse::<u32>().ok()
                    }).is_some_and(|mode| mode & 0x8000_0000 == 0 && mode & 0o111 != 0)
                }) {
                    cmd::outln(&quote(&path));
                } else {
                    report(&format!("{name}: not found"));
                    failure = String::from("not found");
                }
            }
        }
        failure
    }

    fn wait(&mut self, pid: i32) -> String {
        let mut output = [0; 256];
        loop {
            let count = syscall::wait_status(pid, &mut output);
            if count == syscall::EINTR {
                self.dispatch_notes();
                continue;
            }
            return usize::try_from(count).ok().and_then(|count| output.get(..count))
                .and_then(|bytes| core::str::from_utf8(bytes).ok())
                .map_or_else(|| String::from("wait failed"), String::from);
        }
    }

    fn redirect(&mut self, redirects: &[Redirect], restore: &mut Vec<(i64, i64)>, writers: &mut Vec<i32>) -> Result<()> {
        for redirect in redirects {
            let target = match redirect {
                Redirect::File(fd, ..) | Redirect::Dup(fd, _) | Redirect::Here(fd, ..) => *fd,
            };
            let previous = syscall::dup(target);
            restore.push((target, previous));
            match redirect {
                Redirect::Dup(_, Some(source)) => {
                    if *source != target && syscall::dup2(*source, target) < 0 {
                        return Err("can't duplicate descriptor");
                    }
                }
                Redirect::Dup(_, None) => { syscall::close(target); }
                Redirect::Here(_, contents, expand) => {
                    let contents = contents.get().ok_or("missing here document")?;
                    let expanded;
                    let text = if *expand {
                        expanded = self.here_text(contents);
                        &expanded
                    } else {
                        contents
                    };
                    let fds = pipe()?;
                    let writer = match spawn(0) {
                        Ok(pid) => pid,
                        Err(error) => {
                            syscall::close(fds[0]);
                            syscall::close(fds[1]);
                            return Err(error);
                        }
                    };
                    if writer == 0 {
                        syscall::close(fds[0]);
                        syscall::write_all(fds[1], text.as_bytes());
                        syscall::exit(0);
                    }
                    syscall::close(fds[1]);
                    writers.push(writer);
                    install(fds[0], target)?;
                }
                Redirect::File(_, mode, path) => {
                    let path = c_string(self.single(path)?)?;
                    let fd = match mode {
                        FileMode::Read => syscall::open(path.as_ptr(), syscall::OREAD),
                        FileMode::ReadWrite => syscall::open(path.as_ptr(), syscall::ORDWR),
                        FileMode::Write => {
                            let fd = syscall::create3(path.as_ptr(), syscall::OWRITE, 0o666);
                            if fd < 0 && path.starts_with("/proc/") {
                                syscall::open(path.as_ptr(), syscall::OWRITE)
                            } else { fd }
                        }
                        FileMode::Append => {
                            let mut fd = syscall::open(path.as_ptr(), syscall::OWRITE);
                            if fd < 0 {
                                fd = syscall::create3(path.as_ptr(), syscall::OWRITE, 0o666);
                            }
                            if fd >= 0 { syscall::seek(fd, 0, 2); }
                            fd
                        }
                        FileMode::Here => return Err("missing here document"),
                    };
                    if fd < 0 {
                        return Err(if *mode == FileMode::Read { "can't open < file" } else { "can't open > file" });
                    }
                    install(fd, target)?;
                }
            }
        }
        Ok(())
    }

    fn here_text(&self, text: &str) -> String {
        let mut rest = text;
        let mut result = String::new();
        while let Some((head, tail)) = rest.split_once('$') {
            result.push_str(head);
            if let Some(after) = tail.strip_prefix('$') {
                result.push('$');
                rest = after;
            } else {
                let len = syntax::variable_name_len(tail);
                if len != 0 {
                    result.push_str(&self.variable(&tail[..len]).join(" "));
                }
                rest = tail[len..].strip_prefix('^').unwrap_or(&tail[len..]);
            }
        }
        result.push_str(rest);
        result
    }

    fn pipeline(&mut self, output: i64, input: i64, left: &Command, right: &Command) -> Result<String> {
        let [read, write] = pipe()?;
        let producer = match spawn(2) {
            Ok(pid) => pid,
            Err(error) => {
                syscall::close(read);
                syscall::close(write);
                return Err(error);
            }
        };
        if producer == 0 {
            syscall::close(read);
            if install(write, output).is_err() { syscall::exit(1); }
            syscall::exits(&self.execute(left));
        }
        syscall::close(write);
        let original = if input == read { -1 } else { syscall::dup(input) };
        let right_status = install(read, input).map(|()| self.execute(right));
        restore_descriptor(input, original);
        let left_status = self.wait(producer);
        let right_status = right_status?;
        Ok(format!("{left_status}|{right_status}"))
    }

    fn capture(&mut self, body: &Command) -> Result<String> {
        let [read, write] = pipe()?;
        let pid = match spawn(2) {
            Ok(pid) => pid,
            Err(error) => {
                syscall::close(read);
                syscall::close(write);
                return Err(error);
            }
        };
        if pid == 0 {
            syscall::close(read);
            if install(write, 1).is_err() { syscall::exit(1); }
            syscall::exits(&self.execute(body));
        }
        syscall::close(write);
        let output = read_all(read, SOURCE_LIMIT);
        syscall::close(read);
        self.wait(pid);
        output
    }

    fn pipe_file(&mut self, read: bool, body: &Command) -> Result<Vec<Value>> {
        let [reader, writer] = pipe()?;
        let (parent, child, target) = if read { (reader, writer, 1) } else { (writer, reader, 0) };
        match spawn(2 | 4 | 64) {
            Ok(0) => {
                syscall::close(parent);
                if install(child, target).is_err() {
                    syscall::exit(1);
                }
                syscall::exits(&self.execute(body));
            }
            Ok(_) => {
                syscall::close(child);
                self.pipe_files.push(parent);
                Ok(vec![Value::literal(format!("/fd/{parent}"))])
            }
            Err(error) => {
                syscall::close(parent);
                syscall::close(child);
                Err(error)
            }
        }
    }

    fn evaluate(&mut self, source: &str) -> Result<String> {
        let mut input = source.as_bytes();
        self.run_input(|output| {
            let count = input.len().min(output.len());
            output[..count].copy_from_slice(&input[..count]);
            input = &input[count..];
            Ok(count)
        })
    }

    fn run_input(&mut self, mut read: impl FnMut(&mut [u8]) -> Result<usize>) -> Result<String> {
        let previous_condition = self.condition.take();
        let result = (|| {
            let mut source = Vec::new();
            let mut buffer = [0; 512];
            let mut status = self.status.clone();
            loop {
                let count = read(&mut buffer)?;
                if count == 0 {
                    if source.is_empty() {
                        return Ok(status);
                    }
                    if source.last() != Some(&b'\n') {
                        self.append_input(&mut source, b"\n")?;
                    }
                    return self.execute_input(&source)?.ok_or("incomplete command");
                }
                for line in buffer[..count].split_inclusive(|byte| *byte == b'\n') {
                    self.append_input(&mut source, line)?;
                    if line.ends_with(b"\n") {
                        if let Some(result) = self.execute_input(&source)? {
                            status = result;
                            source.clear();
                        }
                    }
                }
            }
        })();
        self.condition = previous_condition;
        result
    }

    fn append_input(&self, source: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
        if source.len() + bytes.len() > SOURCE_LIMIT {
            return Err("input exceeds shell limit");
        }
        if self.flag(b'v') {
            syscall::write_all(2, bytes);
        }
        source.extend_from_slice(bytes);
        Ok(())
    }

    fn execute_input(&mut self, source: &[u8]) -> Result<Option<String>> {
        let source = core::str::from_utf8(source).map_err(|_| "invalid UTF-8 input")?;
        match syntax::parse(source, self.condition.is_some()) {
            Ok(command) => {
                if self.flag(b'r') {
                    syscall::write_all(2, format!("{command:?}\n").as_bytes());
                }
                Ok(Some(self.execute(&command)))
            }
            Err(Error::Incomplete) => Ok(None),
            Err(Error::Invalid(error)) => Err(error),
        }
    }

    fn run_fd(&mut self, fd: i64) -> Result<String> {
        self.run_input(|output| {
            usize::try_from(syscall::read(fd, output.as_mut_ptr(), output.len())).map_err(|_| "read failed")
        })
    }

    fn source(&mut self, path: &str, optional: bool) -> Result<String> {
        let path = c_string(String::from(path))?;
        let fd = syscall::open(path.as_ptr(), syscall::OREAD | syscall::OCEXEC);
        if fd < 0 {
            return if optional { Ok(String::new()) } else { Err("cannot read script") };
        }
        let result = self.run_fd(fd);
        syscall::close(fd);
        result
    }

    fn login(&mut self, startup: &str) -> Result<()> {
        let mut cputype = [0; 32];
        if let Some(count) = env::read_path("#ec/cputype", &mut cputype) {
            if let Ok(architecture) = core::str::from_utf8(&cputype[..count]) {
                for name in ["cputype", "objtype"] {
                    if env::read_value(name, &mut [0]).is_none() {
                        self.set(name, &[String::from(architecture)])?;
                    }
                }
            }
        }
        let mut user = [0; 32];
        let count = syscall::getuser(&mut user);
        let mut home = String::from("/");
        if let Ok(count) = usize::try_from(count) {
            if let Some(name) = user.get(..count).and_then(|value| core::str::from_utf8(value).ok()) {
                self.set("user", &[String::from(name)])?;
                if let Some(account) = cmd::passwd::lookup_name(name) {
                    home = String::from(account.home_str());
                }
            }
        }
        self.set("home", &[home])?;
        self.source(startup, false)?;
        if let Some(home) = self.variable("home").first() {
            self.source(&format!("{home}/lib/profile"), true)?;
        }
        self.status.clear();
        Ok(())
    }
}

use alloc::string::ToString;

fn report(error: &str) {
    syscall::write_all(2, format!("rc: {error}\n").as_bytes());
}

fn quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "''"))
}

fn decimal_prefix(text: &str) -> (usize, &str) {
    let mut number = 0usize;
    let mut digits = 0;
    for digit in text.bytes().take_while(u8::is_ascii_digit) {
        number = number.saturating_mul(10).saturating_add(usize::from(digit - b'0'));
        digits += 1;
    }
    (number, &text[digits..])
}

fn expand_values(values: Vec<String>, style: Expansion) -> Vec<Value> {
    match style {
        Expansion::Count => vec![Value::literal(values.len().to_string())],
        Expansion::Join => vec![Value::literal(values.join(" "))],
        Expansion::List => values.into_iter().map(Value::literal).collect(),
    }
}

fn c_string(mut text: String) -> Result<String> {
    if text.as_bytes().contains(&0) || text.len() > 254 {
        return Err("invalid or too long path");
    }
    text.push('\0');
    Ok(text)
}

fn read_all(fd: i64, limit: usize) -> Result<String> {
    let mut contents = Vec::new();
    let mut buffer = [0; 512];
    loop {
        let count = syscall::read(fd, buffer.as_mut_ptr(), buffer.len());
        if count < 0 { return Err("read failed"); }
        if count == 0 { break; }
        if contents.len() + count as usize > limit { return Err("input exceeds shell limit"); }
        contents.extend_from_slice(&buffer[..count as usize]);
    }
    String::from_utf8(contents).map_err(|_| "invalid UTF-8 input")
}

fn encode_words(words: &[String]) -> Vec<u8> {
    let mut result = Vec::new();
    for word in words {
        result.extend_from_slice(word.as_bytes());
        result.push(0);
    }
    result
}

fn read_env(name: &str) -> Option<Vec<String>> {
    let mut bytes = [0; 4096];
    let count = env::read_value(name, &mut bytes)?;
    Some(env::words(&bytes[..count]).map(|value| String::from_utf8_lossy(value).into_owned()).collect())
}

fn spawn(flags: u32) -> Result<i32> {
    let pid = if flags == 0 {
        syscall::fork()
    } else {
        syscall::rfork(syscall::RFPROC | syscall::RFFDG | flags)
    };
    if pid < 0 { Err("fork failed") } else { Ok(pid as i32) }
}

fn pipe() -> Result<[i64; 2]> {
    let mut fds = [-1; 2];
    if syscall::pipe(&mut fds) < 0 { Err("pipe failed") } else { Ok(fds) }
}

fn install(fd: i64, target: i64) -> Result<()> {
    if fd != target {
        let result = syscall::dup2(fd, target);
        syscall::close(fd);
        if result < 0 { return Err("can't install descriptor"); }
    }
    Ok(())
}

fn restore_descriptor(target: i64, original: i64) {
    if original < 0 {
        syscall::close(target);
    } else {
        syscall::dup2(original, target);
        syscall::close(original);
    }
}

fn exec(words: &[String]) -> Result<String> {
    if words.len() > 64 || words.iter().any(|word| word.len() > 254 || word.as_bytes().contains(&0)) {
        return Err("arguments exceed exec limit");
    }
    let strings: Vec<_> = words.iter().map(|word| format!("{word}\0")).collect();
    let mut pointers: Vec<_> = strings.iter().map(|word| word.as_ptr()).collect();
    pointers.push(core::ptr::null());
    for path in command_paths(&words[0]) {
        if let Ok(path) = c_string(path) {
            syscall::exec(path.as_ptr(), pointers.as_ptr());
        }
    }
    Err("not found")
}

fn command_paths(program: &str) -> Vec<String> {
    if ["/", "./", "../", "#"].iter().any(|prefix| program.starts_with(prefix)) {
        return vec![String::from(program)];
    }
    read_env("path").unwrap_or_else(|| vec![String::from("."), String::from("/bin")])
        .into_iter().map(|dir| if dir.is_empty() { String::from(program) } else { format!("{dir}/{program}") }).collect()
}

fn matches(pattern: &Value, text: &str) -> bool {
    let text: Vec<_> = text.chars().collect();
    let mut possible = vec![false; text.len() + 1];
    possible[0] = true;
    let mut pattern_chars = pattern.text.char_indices();
    while let Some((index, character)) = pattern_chars.next() {
        let special = pattern.meta[index];
        if special && character == '*' {
            for position in 0..text.len() {
                possible[position + 1] |= possible[position];
            }
            continue;
        }
        let class = if special && character == '[' {
            let Some((end, _)) = pattern_chars.by_ref().find(|(_, next)| *next == ']') else {
                return false;
            };
            Some(&pattern.text[index + 1..end])
        } else {
            None
        };
        for position in (0..text.len()).rev() {
            let fits = if let Some(class) = class {
                class_matches(class, text[position])
            } else {
                (special && character == '?') || character == text[position]
            };
            possible[position + 1] = possible[position] && fits;
        }
        possible[0] = false;
    }
    possible[text.len()]
}

fn class_matches(class: &str, character: char) -> bool {
    let (class, negate) = class.strip_prefix('~').map_or((class, false), |class| (class, true));
    let mut characters = class.chars().peekable();
    let mut hit = false;
    while let Some(start) = characters.next() {
        let end = if characters.next_if_eq(&'-').is_some() {
            let Some(end) = characters.next() else { return false; };
            end
        } else {
            start
        };
        hit |= (start.min(end)..=start.max(end)).contains(&character);
    }
    hit != negate
}

fn glob(value: Value) -> Vec<String> {
    if !value.meta.contains(&true) {
        return vec![value.text];
    }
    let mut paths = vec![String::new()];
    let mut start = 0;
    for component in value.text.split('/') {
        let end = start + component.len();
        let meta = &value.meta[start..end];
        if meta.contains(&true) {
            let pattern = Value { text: String::from(component), meta: meta.to_vec() };
            let mut found = Vec::new();
            for prefix in paths {
                let mut listing = vec![0; SOURCE_LIMIT];
                let count = cmd::list_dir(if prefix.is_empty() { "." } else { &prefix }, &mut listing);
                if let Some(listing) = usize::try_from(count).ok().and_then(|count| {
                    core::str::from_utf8(listing.get(..count)?).ok()
                }) {
                    for name in listing.lines() {
                        if matches!(name, "." | "..") && !component.starts_with('.') { continue; }
                        if matches(&pattern, name) {
                            found.push(format!("{prefix}{name}"));
                        }
                    }
                }
            }
            paths = found;
        } else {
            for path in &mut paths { path.push_str(component); }
        }
        if end < value.text.len() {
            for path in &mut paths { path.push('/'); }
        }
        start = end + 1;
    }
    paths.retain(|path| {
        let Ok(path) = c_string(path.clone()) else { return false };
        let mut stat = [0; 512];
        syscall::stat(path.as_ptr(), stat.as_mut_ptr(), stat.len()) >= 0
    });
    if paths.is_empty() { vec![value.text] } else { paths.sort_unstable(); paths }
}

fn help() {
    cmd::out_str(&format!("builtins: {}\n\ncommands:\n", BUILTINS.join(" ")));
    for row in COMMANDS.chunks(6) {
        cmd::out_str("  ");
        cmd::outln(&row.join("  "));
    }
    cmd::outln("\nredirection: < > >>    pipelines: cmd | cmd    lists: cmd ; cmd");
}

pub fn main(argc: usize, argv: *const *const u8) -> i32 {
    syscall::notify(Some(handle_note));
    let mut shell = Shell::default();
    let mut position = 1;
    let mut expression = None;
    let mut startup = None;
    let invocation = cmd::arg(argc, argv, 0).unwrap_or("rc");
    if invocation.starts_with('-') {
        let _ = shell.set_flag(b'l', true);
    }
    while let Some(option) = cmd::arg(argc, argv, position) {
        let Some(options) = option.strip_prefix('-').filter(|options| !options.is_empty()) else { break };
        position += 1;
        if options == "-" {
            break;
        }
        for (index, flag) in options.bytes().enumerate() {
            if let Err(error) = shell.set_flag(flag, true) {
                report(error);
                return 1;
            }
            if matches!(flag, b'c' | b'm') {
                let argument = if index + 1 < options.len() {
                    Some(&options[index + 1..])
                } else {
                    let argument = cmd::arg(argc, argv, position);
                    position += 1;
                    argument
                };
                let Some(argument) = argument else { report("missing option argument"); return 1 };
                if flag == b'c' {
                    expression = Some(argument);
                } else {
                    startup = Some(argument);
                }
                break;
            }
        }
        if expression.is_some() {
            break;
        }
    }
    let login = shell.flag(b'l');
    if syscall::rfork(syscall::RFENVG) < 0 {
        report("cannot copy shell environment");
        return 1;
    }
    shell.import_functions();
    if env::read_value("path", &mut [0]).is_none() {
        env::set_value("path", DEFAULT_PATH);
    }
    let script = if expression.is_none() { cmd::arg(argc, argv, position) } else { None };
    shell.zero = String::from(script.unwrap_or(invocation));
    shell.args = (position + usize::from(script.is_some())..argc)
        .filter_map(|index| cmd::arg(argc, argv, index)).map(String::from).collect();
    if let Some(expression) = expression {
        let _ = shell.set("cflag", &[String::from(expression)]);
    }
    if login {
        if let Err(error) = shell.login(startup.unwrap_or("/rc/lib/rcmain")) {
            report(error);
            return 1;
        }
    } else if let Some(startup) = startup {
        if let Err(error) = shell.source(startup, false) {
            report(error);
            return 1;
        }
    }
    let mut stat = [0; 128];
    let terminal = usize::try_from(syscall::fstat(0, &mut stat)).ok()
        .and_then(|count| stat.get(..count)).and_then(cmd::stat_name) == Some(b"cons");
    let interactive = !shell.flag(b'I') && (shell.flag(b'i') || terminal);
    let result = if let Some(expression) = expression {
        Some(shell.evaluate(expression))
    } else if let Some(script) = script {
        Some(shell.source(script, false))
    } else if !interactive {
        Some(shell.run_fd(0))
    } else {
        None
    };
    if let Some(result) = result {
        let status = result.unwrap_or_else(|error| { report(error); String::from(error) });
        if shell.flag(b's') && !status.is_empty() {
            syscall::write_all(2, format!("{status}\n").as_bytes());
        }
        syscall::exits(&shell.exit_status(status));
    }
    cmd::out_str("\nPlan 9 from Outer Space — Rust kernel\nrc (Rust) — type `help` for a list of commands\n\n");
    let mut line = [0; lineedit::MAX_LINE];
    let mut history = lineedit::History::new();
    let mut source = String::new();
    loop {
        shell.dispatch_notes();
        if let Some(prompt) = read_env("prompt").and_then(|values| values.get(usize::from(!source.is_empty())).cloned()) {
            cmd::out_str(&prompt);
        } else if source.is_empty() { lineedit::prompt(); } else { cmd::out_str("\t"); }
        let count = match lineedit::edit_line(&mut line, &mut history) {
            lineedit::Edit::Line(count) => count,
            lineedit::Edit::Eof => {
                source.clear();
                syscall::sleep_ms(50);
                continue;
            }
        };
        if count == 0 && source.is_empty() { continue; }
        history.push(&line[..count]);
        let Ok(text) = core::str::from_utf8(&line[..count]) else { report("invalid UTF-8 input"); continue };
        if source.len() + text.len() >= SOURCE_LIMIT {
            report("input exceeds shell limit");
            source.clear();
            continue;
        }
        source.push_str(text);
        source.push('\n');
        if shell.flag(b'v') {
            syscall::write_all(2, format!("{text}\n").as_bytes());
        }
        match syntax::parse(&source, shell.condition.is_some()) {
            Err(Error::Incomplete) => continue,
            Err(Error::Invalid(error)) => { report(error); shell.status = String::from(error); }
            Ok(command) => {
                let status = shell.execute(&command);
                if shell.flag(b's') && !status.is_empty() {
                    syscall::write_all(2, format!("{status}\n").as_bytes());
                }
            }
        }
        source.clear();
    }
}
