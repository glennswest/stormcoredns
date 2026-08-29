//! Corefile parser: turns a token stream into server blocks.
//!
//! Mirrors caddy/caddyfile/parse.go:
//! * a server block is one or more keys (addresses/zones) followed by a
//!   `{ ... }` body; a single block may omit the braces;
//! * inside a body, each directive starts a new line: name, arguments on the
//!   same line, and an optional nested `{ ... }` block whose tokens are kept
//!   verbatim for the plugin's own parser;
//! * `import <file|glob|snippet>` splices tokens in place;
//! * `(name) { ... }` at top level defines a snippet;
//! * `{$VAR}` and `{%VAR%}` are replaced with environment variables.

use super::lexer::{lex, Token};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct ServerBlock {
    /// Raw keys, e.g. `.:53`, `example.org`, `tls://.`.
    pub keys: Vec<String>,
    /// Directives in order of appearance. Same-named directives that appear
    /// more than once are kept as separate entries (plugins that permit
    /// repetition see them all via `Controller`).
    pub directives: Vec<Directive>,
    pub line: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Directive {
    pub name: String,
    /// Every token of the directive including the name token, its arguments
    /// and any nested block (with its `{` and `}` tokens).
    pub tokens: Vec<Token>,
}

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    snippets: HashMap<String, Vec<Token>>,
    base_dir: PathBuf,
    import_depth: usize,
}

const MAX_IMPORT_DEPTH: usize = 20;

pub fn parse_file(path: &Path) -> Result<Vec<ServerBlock>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading Corefile {}", path.display()))?;
    parse_str(&text, &path.display().to_string(), path.parent().unwrap_or(Path::new(".")))
}

pub fn parse_str(text: &str, file: &str, base_dir: &Path) -> Result<Vec<ServerBlock>> {
    let tokens = expand_env(lex(text, file));
    let mut p = Parser {
        tokens,
        pos: 0,
        snippets: HashMap::new(),
        base_dir: base_dir.to_path_buf(),
        import_depth: 0,
    };
    p.parse_all()
}

/// Replace `{$VAR}` / `{%VAR%}` with the environment variable's value (empty
/// if unset), exactly like Caddy v1.
pub fn expand_env(tokens: Vec<Token>) -> Vec<Token> {
    tokens
        .into_iter()
        .map(|mut t| {
            if t.text.contains("{$") || t.text.contains("{%") {
                t.text = expand_env_str(&t.text);
            }
            t
        })
        .collect()
}

fn expand_env_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    loop {
        let (open, close) = match (rest.find("{$"), rest.find("{%")) {
            (Some(a), Some(b)) if a <= b => (a, "}"),
            (Some(a), None) => (a, "}"),
            (_, Some(b)) => (b, "%}"),
            (None, None) => break,
        };
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        match after.find(close) {
            Some(end) => {
                let var = &after[..end];
                let val = std::env::var(var).unwrap_or_default();
                out.push_str(&val);
                rest = &after[end + close.len()..];
            }
            None => {
                out.push_str(&rest[open..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }
    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn err(&self, msg: &str) -> anyhow::Error {
        match self.tokens.get(self.pos.min(self.tokens.len().saturating_sub(1))) {
            Some(t) => anyhow!("{}:{} - Error during parsing: {}", t.file, t.line, msg),
            None => anyhow!("Error during parsing: {}", msg),
        }
    }

    fn parse_all(&mut self) -> Result<Vec<ServerBlock>> {
        let mut blocks = Vec::new();
        while self.peek().is_some() {
            // snippet definition
            if let Some(t) = self.peek() {
                if t.text.starts_with('(') && t.text.ends_with(')') && t.text.len() > 2 && !t.quoted {
                    let name = t.text[1..t.text.len() - 1].to_string();
                    self.next();
                    let open = self.next().ok_or_else(|| self.err("expected '{' after snippet name"))?;
                    if open.text != "{" || open.quoted {
                        bail!("{}:{} - Error during parsing: expected '{{' after snippet name", open.file, open.line);
                    }
                    let body = self.collect_block_body()?;
                    self.snippets.insert(name, body);
                    continue;
                }
            }
            let block = self.parse_server_block(blocks.is_empty())?;
            blocks.push(block);
        }
        Ok(blocks)
    }

    /// Consumes tokens up to and including the matching `}` (the opening `{`
    /// has already been consumed) and returns everything in between.
    fn collect_block_body(&mut self) -> Result<Vec<Token>> {
        let mut depth = 1usize;
        let mut body = Vec::new();
        loop {
            let t = self.next().ok_or_else(|| self.err("unexpected EOF, unbalanced braces"))?;
            if !t.quoted {
                if t.text == "{" {
                    depth += 1;
                } else if t.text == "}" {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(body);
                    }
                }
            }
            body.push(t);
        }
    }

    fn parse_server_block(&mut self, first: bool) -> Result<ServerBlock> {
        let mut sb = ServerBlock::default();
        // keys: everything on the same line until `{`
        let start = self.next().ok_or_else(|| self.err("expected server block key"))?;
        sb.line = start.line;
        if !start.quoted && start.text == "{" {
            bail!("{}:{} - Error during parsing: Unexpected token '{{', expecting address", start.file, start.line);
        }
        let mut keys = vec![start.text.clone()];
        let key_line = start.line;
        let mut have_brace = false;
        while let Some(t) = self.peek() {
            if t.line != key_line {
                break;
            }
            if !t.quoted && t.text == "{" {
                self.next();
                have_brace = true;
                break;
            }
            if !t.quoted && t.text == "}" {
                return Err(self.err("unexpected '}' in server block keys"));
            }
            keys.push(t.text.clone());
            self.next();
        }
        // keys may be comma separated: "a, b, c"
        sb.keys = keys
            .iter()
            .flat_map(|k| k.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>())
            .filter(|k| !k.is_empty())
            .collect();

        // body
        let body_tokens: Vec<Token> = if have_brace {
            self.collect_block_body()?
        } else {
            // brace-less block: only allowed for a single-block file; consume
            // everything to EOF.
            if !first {
                return Err(self.err("expected '{' after server block keys"));
            }
            let mut rest = Vec::new();
            while let Some(t) = self.next() {
                rest.push(t);
            }
            rest
        };
        sb.directives = self.parse_directives(body_tokens)?;
        Ok(sb)
    }

    /// Splits a block body into directives, resolving `import` in place.
    fn parse_directives(&mut self, tokens: Vec<Token>) -> Result<Vec<Directive>> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < tokens.len() {
            let name_tok = &tokens[i];
            if !name_tok.quoted && (name_tok.text == "{" || name_tok.text == "}") {
                bail!("{}:{} - Error during parsing: unexpected '{}'", name_tok.file, name_tok.line, name_tok.text);
            }
            let line = name_tok.line;
            let mut dir_tokens = vec![name_tok.clone()];
            i += 1;
            // args on the same line
            while i < tokens.len() && tokens[i].line == line && !(tokens[i].text == "{" && !tokens[i].quoted) {
                if !tokens[i].quoted && tokens[i].text == "}" {
                    bail!("{}:{} - Error during parsing: unexpected '}}'", tokens[i].file, tokens[i].line);
                }
                dir_tokens.push(tokens[i].clone());
                i += 1;
            }
            // nested block: `{` on the same line as the directive name
            if i < tokens.len() && tokens[i].line == line && tokens[i].text == "{" && !tokens[i].quoted {
                let mut depth = 0usize;
                loop {
                    if i >= tokens.len() {
                        bail!("{}:{} - Error during parsing: unbalanced braces in directive '{}'", name_tok.file, line, name_tok.text);
                    }
                    let t = &tokens[i];
                    if !t.quoted && t.text == "{" {
                        depth += 1;
                    } else if !t.quoted && t.text == "}" {
                        depth -= 1;
                    }
                    dir_tokens.push(t.clone());
                    i += 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
            if name_tok.text == "import" && !name_tok.quoted {
                let imported = self.do_import(&dir_tokens)?;
                out.extend(imported);
                continue;
            }
            out.push(Directive { name: name_tok.text.clone(), tokens: dir_tokens });
        }
        Ok(out)
    }

    fn do_import(&mut self, dir: &[Token]) -> Result<Vec<Directive>> {
        if dir.len() != 2 {
            bail!("{}:{} - Error during parsing: import takes exactly one argument (a snippet name or file pattern)", dir[0].file, dir[0].line);
        }
        if self.import_depth >= MAX_IMPORT_DEPTH {
            bail!("{}:{} - Error during parsing: import nesting too deep", dir[0].file, dir[0].line);
        }
        let arg = &dir[1].text;
        let mut tokens: Vec<Token> = Vec::new();
        if let Some(snip) = self.snippets.get(arg) {
            tokens = snip.clone();
        } else {
            let pat = if Path::new(arg).is_absolute() {
                PathBuf::from(arg)
            } else {
                self.base_dir.join(arg)
            };
            let pat_s = pat.to_string_lossy().to_string();
            let mut matched = Vec::new();
            for entry in glob::glob(&pat_s).map_err(|e| anyhow!("{}:{} - Error during parsing: bad import pattern {}: {}", dir[0].file, dir[0].line, arg, e))? {
                if let Ok(p) = entry {
                    if p.is_file() {
                        matched.push(p);
                    }
                }
            }
            if matched.is_empty() {
                // Caddy: importing a non-existent literal file is an error,
                // an empty glob is not.
                let has_glob = arg.contains('*') || arg.contains('?') || arg.contains('[');
                if !has_glob {
                    bail!("{}:{} - Error during parsing: could not import {}: file not found", dir[0].file, dir[0].line, arg);
                }
            }
            matched.sort();
            for p in matched {
                let text = std::fs::read_to_string(&p)
                    .with_context(|| format!("importing {}", p.display()))?;
                tokens.extend(expand_env(lex(&text, &p.display().to_string())));
            }
        }
        self.import_depth += 1;
        let r = self.parse_directives(tokens);
        self.import_depth -= 1;
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Vec<ServerBlock> {
        parse_str(s, "Corefile", Path::new(".")).unwrap()
    }

    #[test]
    fn single_block_with_braces() {
        let b = parse(".:1053 {\n  whoami\n  log\n  forward . 8.8.8.8 {\n    max_fails 2\n  }\n}\n");
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].keys, vec![".:1053"]);
        let names: Vec<&str> = b[0].directives.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["whoami", "log", "forward"]);
        assert_eq!(b[0].directives[2].tokens.len(), 7);
    }

    #[test]
    fn multiple_blocks_and_keys() {
        let b = parse("example.org, example.net:53 {\n whoami\n}\ntls://. {\n forward . 1.1.1.1\n}\n");
        assert_eq!(b.len(), 2);
        assert_eq!(b[0].keys, vec!["example.org", "example.net:53"]);
        assert_eq!(b[1].keys, vec!["tls://."]);
    }

    #[test]
    fn braceless_single_block() {
        let b = parse(".\nwhoami\nlog\n");
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].directives.len(), 2);
    }

    #[test]
    fn snippet_import() {
        let b = parse("(common) {\n  log\n  errors\n}\n. {\n  import common\n  whoami\n}\n");
        assert_eq!(b.len(), 1);
        let names: Vec<&str> = b[0].directives.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["log", "errors", "whoami"]);
    }

    #[test]
    fn env_expansion() {
        std::env::set_var("STORMCOREDNS_TEST_PORT", "5300");
        let b = parse(".:{$STORMCOREDNS_TEST_PORT} {\n whoami\n}\n");
        assert_eq!(b[0].keys, vec![".:5300"]);
    }

    #[test]
    fn directive_block_must_open_on_same_line() {
        let r = parse_str(". {\n  cache 30\n  {\n  }\n}\n", "Corefile", Path::new("."));
        assert!(r.is_err());
    }
}
