use alloc::{boxed::Box, rc::Rc, string::String, vec::Vec};
use core::cell::OnceCell;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FileMode {
    Read,
    Write,
    Append,
    ReadWrite,
    Here,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Expansion {
    List,
    Count,
    Join,
}

#[derive(Clone, Debug)]
pub enum Word {
    Literal(String, bool),
    List(Vec<Word>),
    Variable(String, Expansion, Option<Vec<Word>>),
    Indirect(Box<Word>, Expansion, Option<Vec<Word>>),
    Concat(Box<Word>, Box<Word>),
    Substitute(Box<Command>),
    PipeFile(bool, Box<Command>),
}

#[derive(Clone, Debug)]
pub enum Redirect {
    File(i64, FileMode, Word),
    Dup(i64, Option<i64>),
    Here(i64, Rc<OnceCell<String>>, bool),
}

#[derive(Clone, Debug)]
pub enum Command {
    Sequence(Vec<Command>),
    Background(Box<Command>),
    Conditional(bool, Box<Command>, Box<Command>),
    Pipe(i64, i64, Box<Command>, Box<Command>),
    Negate(Box<Command>),
    Subshell(Box<Command>),
    If(Box<Command>, Box<Command>),
    Otherwise(Box<Command>),
    While(Box<Command>, Box<Command>),
    For(Word, Option<Vec<Word>>, Box<Command>),
    Switch(Word, Vec<Case>),
    Function(Vec<Word>, Option<Rc<Function>>),
    Match(Word, Vec<Word>),
    Simple(Vec<Word>),
    Assigned(Vec<(Word, Word)>, Box<Command>),
    Redirected(Vec<Redirect>, Box<Command>),
}

#[derive(Clone, Debug)]
pub struct Case {
    pub patterns: Vec<Word>,
    pub body: Command,
}

#[derive(Clone, Debug)]
pub struct Function {
    pub body: Command,
    pub source: String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    Incomplete,
    Invalid(&'static str),
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Literal(String, bool),
    Variable(String, Expansion),
    Open,
    Close,
    Brace,
    EndBrace,
    Newline,
    Semi,
    And,
    Or,
    Background,
    Pipe(i64, i64),
    File(i64, FileMode),
    Dup(i64, Option<i64>),
    Equals,
    Concat,
    Backquote,
    PipeFile(bool),
    End,
}

struct Lexer<'a> {
    source: &'a str,
    separated: bool,
}

pub(super) fn variable_name_len(source: &str) -> usize {
    source.bytes().take_while(|byte| {
        *byte > b' ' && !b"!\"#$%&'()+,-./:;<=>?@[\\]^`{|}~".contains(byte)
    }).count()
}

impl<'a> Lexer<'a> {
    fn consume(&mut self, bytes: usize) -> &'a str {
        let (head, tail) = self.source.split_at(bytes);
        self.source = tail;
        head
    }

    fn take(&mut self, prefix: &str) -> bool {
        if self.source.starts_with(prefix) {
            self.consume(prefix.len());
            true
        } else {
            false
        }
    }

    fn fd(&mut self) -> Result<i64, Error> {
        let len = self.source.bytes().take_while(u8::is_ascii_digit).count();
        self.consume(len).parse().map_err(|_| Error::Invalid("invalid file descriptor"))
    }

    fn quoted(&mut self) -> Result<String, Error> {
        let mut text = String::new();
        loop {
            let quote = self.source.find('\'').ok_or(Error::Incomplete)?;
            text.push_str(self.consume(quote));
            self.consume(1);
            if !self.take("'") {
                return Ok(text);
            }
            text.push('\'');
        }
    }

    fn next(&mut self) -> Result<Token, Error> {
        self.separated = false;
        loop {
            if self.take(" ") || self.take("\t") || self.take("\r") {
                self.separated = true;
            } else if self.take("\\\n") {
                if self.source.is_empty() {
                    return Err(Error::Incomplete);
                }
                self.separated = true;
            } else if self.source.starts_with('#') {
                self.consume(self.source.find('\n').unwrap_or(self.source.len()));
                self.separated = true;
            } else {
                break;
            }
        }
        let Some(byte) = self.source.as_bytes().first().copied() else { return Ok(Token::End) };
        if byte.is_ascii() {
            self.consume(1);
        }
        let token = match byte {
            b'(' => Token::Open,
            b')' => Token::Close,
            b'{' => Token::Brace,
            b'}' => Token::EndBrace,
            b'\n' => Token::Newline,
            b';' => Token::Semi,
            b'=' => Token::Equals,
            b'^' => Token::Concat,
            b'`' => Token::Backquote,
            b'\'' => Token::Literal(self.quoted()?, true),
            b'$' => {
                let kind = if self.take("#") { Expansion::Count }
                    else if self.take("\"") { Expansion::Join }
                    else { Expansion::List };
                let name = if self.take("'") {
                    self.quoted()?
                } else {
                    let length = variable_name_len(self.source);
                    String::from(self.consume(length))
                };
                Token::Variable(name, kind)
            }
            b'&' if self.take("&") => Token::And,
            b'&' => Token::Background,
            b'|' if self.take("|") => Token::Or,
            b'<' | b'>' if self.source.trim_start_matches([' ', '\t']).starts_with('{') => Token::PipeFile(byte == b'<'),
            b'|' | b'<' | b'>' => {
                let (default, mode) = match byte {
                    b'|' => (1, FileMode::Write),
                    b'<' if self.take("<") => (0, FileMode::Here),
                    b'<' if self.take(">") => (0, FileMode::ReadWrite),
                    b'<' => (0, FileMode::Read),
                    b'>' if self.take(">") => (1, FileMode::Append),
                    b'>' => (1, FileMode::Write),
                    _ => unreachable!(),
                };
                let mut output = default;
                let mut input = None;
                let mut has_equals = false;
                if self.take("[") {
                    output = self.fd()?;
                    has_equals = self.take("=");
                    if has_equals && !self.source.starts_with(']') {
                        input = Some(self.fd()?);
                    }
                    if !self.take("]") {
                        return Err(Error::Invalid("missing ] after file descriptor"));
                    }
                }
                if byte == b'|' {
                    if has_equals && input.is_none() {
                        return Err(Error::Invalid("pipe requires an input descriptor"));
                    }
                    Token::Pipe(output, input.unwrap_or(0))
                } else if has_equals {
                    if matches!(mode, FileMode::Here | FileMode::Append) {
                        return Err(Error::Invalid("invalid descriptor duplication"));
                    }
                    Token::Dup(output, input)
                } else {
                    Token::File(output, mode)
                }
            }
            _ => {
                let bytes = self.source.as_bytes();
                let length = bytes.iter().enumerate().take_while(|(index, byte)| {
                    !b" \t\r\n'(){};=&|<>^`$#".contains(byte)
                        && !(**byte == b'\\' && bytes.get(index + 1) == Some(&b'\n'))
                }).count();
                let mut word = String::new();
                if byte.is_ascii() {
                    word.push(byte as char);
                }
                word.push_str(self.consume(length));
                Token::Literal(word, false)
            }
        };
        Ok(token)
    }

    fn here(&mut self, delimiter: &str) -> Result<String, Error> {
        let mut document = String::new();
        loop {
            let end = self.source.find('\n').ok_or(Error::Incomplete)?;
            let line = self.consume(end + 1);
            if &line[..end] == delimiter {
                return Ok(document);
            }
            document.push_str(line);
        }
    }
}

struct Parser<'a> {
    lexer: Lexer<'a>,
    token: Token,
    depth: usize,
    documents: Vec<(String, Rc<OnceCell<String>>)>,
}

pub fn parse(source: &str) -> Result<Command, Error> {
    let mut parser = Parser {
        lexer: Lexer { source, separated: true },
        token: Token::End,
        depth: 0,
        documents: Vec::new(),
    };
    parser.bump()?;
    let command = parser.sequence(false)?;
    parser.expect(Token::End)?;
    Ok(command)
}

impl Parser<'_> {
    fn bump(&mut self) -> Result<Token, Error> {
        if self.token == Token::Newline {
            for (delimiter, contents) in self.documents.drain(..) {
                let _ = contents.set(self.lexer.here(&delimiter)?);
            }
        }
        if self.token == Token::End && !self.documents.is_empty() {
            return Err(Error::Incomplete);
        }
        Ok(core::mem::replace(&mut self.token, self.lexer.next()?))
    }

    fn is(&self, word: &str) -> bool {
        matches!(&self.token, Token::Literal(text, false) if text == word)
    }

    fn fail(&self, why: &'static str) -> Error {
        if self.token == Token::End { Error::Incomplete } else { Error::Invalid(why) }
    }

    fn expect(&mut self, token: Token) -> Result<(), Error> {
        if self.token != token {
            return Err(self.fail("unexpected token"));
        }
        self.bump()?;
        Ok(())
    }

    fn skip_newlines(&mut self) -> Result<(), Error> {
        while self.token == Token::Newline {
            self.bump()?;
        }
        Ok(())
    }

    fn continuation(&mut self) -> Result<(), Error> {
        self.skip_newlines()?;
        if self.token == Token::End { Err(Error::Incomplete) } else { Ok(()) }
    }

    fn nested<T>(&mut self, parse: impl FnOnce(&mut Self) -> Result<T, Error>) -> Result<T, Error> {
        if self.depth == 48 {
            return Err(Error::Invalid("command nesting too deep"));
        }
        self.depth += 1;
        let result = parse(self);
        self.depth -= 1;
        result
    }

    fn sequence(&mut self, cases: bool) -> Result<Command, Error> {
        let mut commands = Vec::new();
        loop {
            while matches!(self.token, Token::Newline | Token::Semi) {
                self.bump()?;
            }
            if matches!(self.token, Token::End | Token::EndBrace | Token::Close) || (cases && self.is("case")) {
                return Ok(Command::Sequence(commands));
            }
            let mut command = self.command(1)?;
            match self.token {
                Token::Background => {
                    self.bump()?;
                    command = Command::Background(Box::new(command));
                }
                Token::Semi | Token::Newline => {
                    self.bump()?;
                }
                Token::Close | Token::EndBrace | Token::End => {}
                _ => return Err(Error::Invalid("expected command separator")),
            }
            commands.push(command);
        }
    }

    fn command(&mut self, min: u8) -> Result<Command, Error> {
        self.nested(|parser| {
            let left = parser.prefix()?;
            parser.continue_command(left, min)
        })
    }

    fn continue_command(&mut self, mut left: Command, min: u8) -> Result<Command, Error> {
        loop {
            let strength = match self.token {
                Token::And | Token::Or => 1,
                Token::Pipe(..) => 3,
                _ => break,
            };
            if strength < min { break; }
            let op = self.bump()?;
            self.continuation()?;
            let right = Box::new(self.command(strength + 1)?);
            left = match op {
                Token::And | Token::Or => Command::Conditional(op == Token::And, Box::new(left), right),
                Token::Pipe(output, input) => Command::Pipe(output, input, Box::new(left), right),
                _ => unreachable!(),
            };
        }
        Ok(left)
    }

    fn body(&mut self, open: Token, close: Token) -> Result<Command, Error> {
        self.expect(open)?;
        let command = self.nested(|parser| parser.sequence(false))?;
        self.expect(close)?;
        Ok(command)
    }

    fn prefix(&mut self) -> Result<Command, Error> {
        let command = if matches!(self.token, Token::File(..) | Token::Dup(..)) {
            let redirects = self.redirects()?;
            return Ok(Self::redirected(redirects, self.command(2)?));
        } else if matches!(self.token, Token::End | Token::Newline | Token::EndBrace | Token::Close | Token::Semi) {
            Command::Simple(Vec::new())
        } else if self.is("if") {
            self.bump()?;
            if self.is("not") {
                self.bump()?;
                self.continuation()?;
                return Ok(Command::Otherwise(Box::new(self.command(1)?)));
            }
            let condition = self.body(Token::Open, Token::Close)?;
            self.continuation()?;
            Command::If(Box::new(condition), Box::new(self.command(1)?))
        } else if self.is("while") {
            self.bump()?;
            let mut condition = self.body(Token::Open, Token::Close)?;
            if matches!(&condition, Command::Sequence(commands) if commands.is_empty()) {
                condition = Command::Simple(Vec::new());
            }
            self.continuation()?;
            Command::While(Box::new(condition), Box::new(self.command(1)?))
        } else if self.is("for") {
            self.bump()?;
            self.expect(Token::Open)?;
            let name = self.word()?;
            let values = if self.is("in") {
                self.bump()?;
                Some(self.words()?)
            } else { None };
            self.expect(Token::Close)?;
            self.continuation()?;
            Command::For(name, values, Box::new(self.command(1)?))
        } else if self.is("switch") {
            self.bump()?;
            let subject = self.word()?;
            self.skip_newlines()?;
            self.expect(Token::Brace)?;
            let mut cases = Vec::new();
            self.skip_newlines()?;
            while self.is("case") {
                self.bump()?;
                let patterns = self.words()?;
                if !matches!(self.token, Token::Semi | Token::Newline | Token::EndBrace) {
                    return Err(self.fail("expected separator after case patterns"));
                }
                let body = self.nested(|parser| parser.sequence(true))?;
                cases.push(Case { patterns, body });
            }
            self.expect(Token::EndBrace)?;
            Command::Switch(subject, cases)
        } else if self.is("fn") {
            self.bump()?;
            let names = self.words()?;
            let body = if self.token == Token::Brace {
                let source = self.lexer.source;
                self.bump()?;
                let body = self.nested(|parser| parser.sequence(false))?;
                if self.token != Token::EndBrace {
                    return Err(self.fail("expected closing brace"));
                }
                let length = source.len() - self.lexer.source.len() - 1;
                self.bump()?;
                Some(Rc::new(Function { body, source: String::from(&source[..length]) }))
            } else { None };
            Command::Function(names, body)
        } else if self.is("~") {
            self.bump()?;
            Command::Match(self.word()?, self.words()?)
        } else if self.is("!") || self.is("@") {
            let negate = self.is("!");
            self.bump()?;
            let body = Box::new(self.command(2)?);
            if negate { Command::Negate(body) } else { Command::Subshell(body) }
        } else if self.token == Token::Brace {
            self.body(Token::Brace, Token::EndBrace)?
        } else {
            return self.simple();
        };
        let redirects = self.redirects()?;
        Ok(Self::redirected(redirects, command))
    }

    fn simple(&mut self) -> Result<Command, Error> {
        let mut words = Vec::new();
        let mut assigned = Vec::new();
        let mut redirects = Vec::new();
        while self.starts_word() || matches!(self.token, Token::File(..) | Token::Dup(..)) {
            if matches!(self.token, Token::File(..) | Token::Dup(..)) {
                redirects.append(&mut self.redirects()?);
                continue;
            }
            let word = self.word()?;
            if self.token == Token::Equals && words.is_empty() {
                self.bump()?;
                assigned.push((word, self.word()?));
                if matches!(self.token, Token::Brace | Token::File(..) | Token::Dup(..))
                    || ["if", "while", "for", "switch", "fn", "!", "@", "~"].iter().any(|keyword| self.is(keyword))
                {
                    let command = Self::redirected(redirects, self.command(2)?);
                    return Ok(Command::Assigned(assigned, Box::new(command)));
                }
            } else {
                words.push(word);
            }
        }
        if words.is_empty() && assigned.is_empty() && redirects.is_empty() {
            return Err(self.fail("expected command"));
        }
        let command = Self::redirected(redirects, Command::Simple(words));
        if assigned.is_empty() {
            Ok(command)
        } else {
            let command = self.continue_command(command, 2)?;
            Ok(Command::Assigned(assigned, Box::new(command)))
        }
    }

    fn redirected(redirects: Vec<Redirect>, command: Command) -> Command {
        if redirects.is_empty() { command } else { Command::Redirected(redirects, Box::new(command)) }
    }

    fn redirects(&mut self) -> Result<Vec<Redirect>, Error> {
        let mut redirects = Vec::new();
        loop {
            let redirect = match self.token {
                Token::File(fd, mode) => {
                    self.bump()?;
                    let word = self.word()?;
                    if mode == FileMode::Here {
                        let Word::Literal(delimiter, quoted) = word else {
                            return Err(Error::Invalid("here document requires a literal delimiter"));
                        };
                        let contents = Rc::new(OnceCell::new());
                        self.documents.push((delimiter, contents.clone()));
                        Redirect::Here(fd, contents, !quoted)
                    } else {
                        Redirect::File(fd, mode, word)
                    }
                }
                Token::Dup(fd, source) => {
                    self.bump()?;
                    Redirect::Dup(fd, source)
                }
                _ => break,
            };
            redirects.push(redirect);
        }
        Ok(redirects)
    }

    fn starts_word(&self) -> bool {
        matches!(self.token, Token::Literal(..) | Token::Variable(..) | Token::Open | Token::Backquote | Token::PipeFile(_))
    }

    fn words(&mut self) -> Result<Vec<Word>, Error> {
        let mut words = Vec::new();
        while self.starts_word() {
            words.push(self.word()?);
        }
        Ok(words)
    }

    fn word(&mut self) -> Result<Word, Error> {
        if !self.starts_word() {
            return Err(self.fail("expected word"));
        }
        self.nested(|parser| {
            let mut word = parser.atom()?;
            while parser.token == Token::Concat || (!parser.lexer.separated && parser.starts_word()) {
                if parser.token == Token::Concat {
                    parser.bump()?;
                }
                if !parser.starts_word() {
                    return Err(parser.fail("expected word after ^"));
                }
                word = Word::Concat(Box::new(word), Box::new(parser.atom()?));
            }
            Ok(word)
        })
    }

    fn atom(&mut self) -> Result<Word, Error> {
        Ok(match self.bump()? {
            Token::Literal(text, quoted) => Word::Literal(text, quoted),
            Token::Variable(name, style) if name.is_empty() => {
                if !self.starts_word() {
                    return Err(self.fail("missing variable name"));
                }
                let name = self.nested(|parser| parser.atom())?;
                Word::Indirect(Box::new(name), style, self.subscripts()?)
            }
            Token::Variable(name, style) => Word::Variable(name, style, self.subscripts()?),
            Token::Open => {
                let words = self.words()?;
                self.expect(Token::Close)?;
                Word::List(words)
            }
            Token::Backquote => Word::Substitute(Box::new(self.body(Token::Brace, Token::EndBrace)?)),
            Token::PipeFile(read) => Word::PipeFile(read, Box::new(self.body(Token::Brace, Token::EndBrace)?)),
            _ => return Err(Error::Invalid("expected word")),
        })
    }

    fn subscripts(&mut self) -> Result<Option<Vec<Word>>, Error> {
        if self.token != Token::Open || self.lexer.separated {
            return Ok(None);
        }
        self.bump()?;
        let indices = self.words()?;
        self.expect(Token::Close)?;
        Ok(Some(indices))
    }
}
