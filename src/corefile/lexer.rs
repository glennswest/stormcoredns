//! Caddyfile-v1 lexer, as used by CoreDNS's Corefile.
//!
//! Tokenization rules (mirroring caddy/caddyfile/lexer.go):
//! * whitespace separates tokens; newlines are significant and recorded on
//!   the token so the parser can tell "same line" from "next line";
//! * `#` starts a comment to end of line, but only at a token boundary;
//! * `"..."` quoted tokens may span lines and support `\"` escapes;
//! * `` `...` `` raw backtick tokens have no escapes;
//! * a `\` at end of line continues the line (newline is folded away);
//! * `{` and `}` are their own tokens only when standing alone.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub file: String,
    pub line: usize,
    pub text: String,
    /// True when the token came from a quoted string (so `{` and `}` inside
    /// it are literal, and `{$ENV}` expansion was still applied by Caddy).
    pub quoted: bool,
}

impl Token {
    pub fn new(file: &str, line: usize, text: impl Into<String>) -> Self {
        Token { file: file.to_string(), line, text: text.into(), quoted: false }
    }
}

pub fn lex(input: &str, file: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let mut line = 1usize;
    let n = chars.len();

    while i < n {
        let c = chars[i];
        // whitespace
        if c == '\n' {
            line += 1;
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        // comment
        if c == '#' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        // line continuation: backslash followed by newline
        // (caddy folds the newline: the next line is still the same "line"
        // for the parser's same-line argument rule)
        if c == '\\' && i + 1 < n && chars[i + 1] == '\n' {
            i += 2;
            continue;
        }
        if c == '\\' && i + 2 < n && chars[i + 1] == '\r' && chars[i + 2] == '\n' {
            i += 3;
            continue;
        }
        // quoted token
        if c == '"' {
            let start_line = line;
            i += 1;
            let mut s = String::new();
            let mut closed = false;
            while i < n {
                let ch = chars[i];
                if ch == '\\' && i + 1 < n && chars[i + 1] == '"' {
                    s.push('"');
                    i += 2;
                    continue;
                }
                if ch == '"' {
                    i += 1;
                    closed = true;
                    break;
                }
                if ch == '\n' {
                    line += 1;
                }
                s.push(ch);
                i += 1;
            }
            let _ = closed;
            out.push(Token { file: file.to_string(), line: start_line, text: s, quoted: true });
            continue;
        }
        // raw backtick token
        if c == '`' {
            let start_line = line;
            i += 1;
            let mut s = String::new();
            while i < n {
                let ch = chars[i];
                if ch == '`' {
                    i += 1;
                    break;
                }
                if ch == '\n' {
                    line += 1;
                }
                s.push(ch);
                i += 1;
            }
            out.push(Token { file: file.to_string(), line: start_line, text: s, quoted: true });
            continue;
        }
        // bare token
        let start_line = line;
        let mut s = String::new();
        while i < n {
            let ch = chars[i];
            if ch.is_whitespace() {
                break;
            }
            // `#` at a token boundary only; inside a token it's literal.
            s.push(ch);
            i += 1;
        }
        out.push(Token { file: file.to_string(), line: start_line, text: s, quoted: false });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_tokens() {
        let t = lex(". {\n  forward . 8.8.8.8 # comment\n  log\n}\n", "Corefile");
        let v: Vec<&str> = t.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(v, vec![".", "{", "forward", ".", "8.8.8.8", "log", "}"]);
        assert_eq!(t[2].line, 2);
        assert_eq!(t[5].line, 3);
    }

    #[test]
    fn quoted_and_continuation() {
        let t = lex("a \"b c\" \\\n d `e \"f\"`", "x");
        let v: Vec<&str> = t.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(v, vec!["a", "b c", "d", "e \"f\""]);
        assert!(t[1].quoted);
        assert_eq!(t[2].line, 1);
    }

    #[test]
    fn escaped_quote() {
        let t = lex(r#"x "say \"hi\"" y"#, "x");
        assert_eq!(t[1].text, "say \"hi\"");
        assert_eq!(t[2].text, "y");
    }
}
