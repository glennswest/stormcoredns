//! The `Controller`: what a plugin's `setup` function receives.
//!
//! It is Caddy's `Dispenser` (a cursor over the tokens of every occurrence of
//! one directive inside one server block) plus access to the server config
//! being assembled. Method names follow caddy so upstream plugin `setup.go`
//! files translate line for line:
//!
//! ```text
//! for c.Next() {                     while c.next() {
//!     args := c.RemainingArgs()          let args = c.remaining_args();
//!     for c.NextBlock() {                while c.next_block() {
//!         switch c.Val() {                   match c.val() {
//! ```

use super::lexer::Token;
use anyhow::anyhow;
use std::fmt;

#[derive(Debug)]
pub struct ConfigError {
    pub plugin: String,
    pub msg: String,
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "plugin/{}: {}", self.plugin, self.msg)
    }
}
impl std::error::Error for ConfigError {}

/// A token cursor identical in behaviour to caddyfile.Dispenser.
#[derive(Debug, Clone)]
pub struct Dispenser {
    pub tokens: Vec<Token>,
    /// Index of the current token, or `usize::MAX` before the first `next()`.
    cursor: usize,
    nesting: usize,
    started: bool,
}

impl Dispenser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Dispenser { tokens, cursor: 0, nesting: 0, started: false }
    }

    /// Advance to the next token. Returns false at end of input.
    pub fn next(&mut self) -> bool {
        if !self.started {
            self.started = true;
            return !self.tokens.is_empty();
        }
        if self.cursor + 1 < self.tokens.len() {
            self.cursor += 1;
            return true;
        }
        // park past the end so val() is empty
        self.cursor = self.tokens.len();
        false
    }

    /// Advance only if the next token is on the same line as the current one.
    pub fn next_arg(&mut self) -> bool {
        if !self.started {
            return self.next();
        }
        if self.cursor >= self.tokens.len() {
            return false;
        }
        if self.cursor + 1 < self.tokens.len()
            && self.tokens[self.cursor + 1].line == self.tokens[self.cursor].line
        {
            self.cursor += 1;
            return true;
        }
        false
    }

    /// Advance only if the next token is on a *different* line.
    pub fn next_line(&mut self) -> bool {
        if !self.started {
            return self.next();
        }
        if self.cursor >= self.tokens.len() {
            return false;
        }
        if self.cursor + 1 < self.tokens.len()
            && self.tokens[self.cursor + 1].line != self.tokens[self.cursor].line
        {
            self.cursor += 1;
            return true;
        }
        false
    }

    /// Enter a `{ }` block opened on the current line, and then step through
    /// its tokens; returns false when the block is exhausted.
    pub fn next_block(&mut self) -> bool {
        if self.nesting > 0 {
            self.next();
            if self.val() == "}" {
                self.nesting -= 1;
                return false;
            }
            return true;
        }
        if !self.next_arg() {
            return false;
        }
        if self.val() != "{" {
            self.cursor -= 1;
            return false;
        }
        self.next();
        if self.val() == "}" {
            return false;
        }
        self.nesting += 1;
        true
    }

    /// Text of the current token ("" when off the ends).
    pub fn val(&self) -> &str {
        if !self.started || self.cursor >= self.tokens.len() {
            ""
        } else {
            &self.tokens[self.cursor].text
        }
    }

    pub fn current(&self) -> Option<&Token> {
        if !self.started {
            None
        } else {
            self.tokens.get(self.cursor)
        }
    }

    pub fn line(&self) -> usize {
        self.current().map(|t| t.line).unwrap_or(0)
    }

    pub fn file(&self) -> String {
        self.current().map(|t| t.file.clone()).unwrap_or_default()
    }

    /// Load `n` arguments from the current line into the slots; returns
    /// false (without consuming) if fewer than `n` remain on the line.
    pub fn args(&mut self, n: usize) -> Option<Vec<String>> {
        let save = (self.cursor, self.started);
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            if !self.next_arg() {
                self.cursor = save.0;
                self.started = save.1;
                return None;
            }
            out.push(self.val().to_string());
        }
        Some(out)
    }

    /// All remaining tokens on the current line.
    pub fn remaining_args(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while self.next_arg() {
            out.push(self.val().to_string());
        }
        out
    }

    /// Like `remaining_args` but stops at, and does not consume, a `{`.
    pub fn remaining_args_until_brace(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while self.next_arg() {
            if self.val() == "{" {
                self.cursor -= 1;
                break;
            }
            out.push(self.val().to_string());
        }
        out
    }

    /// Consumes and discards the rest of the current block (used to skip
    /// unknown sub-blocks). The cursor must be inside the block.
    pub fn skip_block(&mut self) {
        while self.next_block() {}
    }

    pub fn arg_err(&self) -> anyhow::Error {
        self.err("Wrong argument count or unexpected line ending after")
    }

    pub fn syntax_err(&self, expected: &str) -> anyhow::Error {
        anyhow!(
            "{}:{} - Syntax error: Unexpected token '{}', expecting '{}'",
            self.file(),
            self.line(),
            self.val(),
            expected
        )
    }

    pub fn err(&self, msg: &str) -> anyhow::Error {
        anyhow!("{}:{} - Error during parsing: {} '{}'", self.file(), self.line(), msg, self.val())
    }

    pub fn errf(&self, msg: impl fmt::Display) -> anyhow::Error {
        anyhow!("{}:{} - Error during parsing: {}", self.file(), self.line(), msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corefile::lexer::lex;

    #[test]
    fn walk_directive_with_block() {
        let toks = lex("forward . 8.8.8.8 1.1.1.1 {\n  max_fails 3\n  policy round_robin\n}\nforward example.org 10.0.0.1\n", "t");
        let mut d = Dispenser::new(toks);
        assert!(d.next());
        assert_eq!(d.val(), "forward");
        let args = d.remaining_args_until_brace();
        assert_eq!(args, vec![".", "8.8.8.8", "1.1.1.1"]);
        let mut seen = Vec::new();
        while d.next_block() {
            let k = d.val().to_string();
            let rest = d.remaining_args();
            seen.push((k, rest));
        }
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, "max_fails");
        assert_eq!(seen[1].1, vec!["round_robin"]);
        assert!(d.next());
        assert_eq!(d.val(), "forward");
        assert_eq!(d.remaining_args(), vec!["example.org", "10.0.0.1"]);
        assert!(!d.next());
    }

    #[test]
    fn empty_block() {
        let toks = lex("cache {\n}\n", "t");
        let mut d = Dispenser::new(toks);
        assert!(d.next());
        assert!(!d.next_block());
        assert!(!d.next());
    }

    #[test]
    fn args_rollback() {
        let toks = lex("x a\n", "t");
        let mut d = Dispenser::new(toks);
        d.next();
        assert!(d.args(2).is_none());
        assert_eq!(d.args(1).unwrap(), vec!["a"]);
    }
}
