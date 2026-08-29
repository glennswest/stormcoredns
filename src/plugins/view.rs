//! `view NAME { expr EXPRESSION... }` — split horizon: a server block only
//! answers requests for which every expression is true. Expressions use
//! the CoreDNS/expr-lang syntax:
//!
//! ```text
//! incidr(client_ip(), '10.0.0.0/8') && name() endsWith '.internal.'
//! type() in ['A', 'AAAA'] || not (port() == 53)
//! metadata('geoip/country/code') == 'US'
//! name() matches '^[a-z]+\\.example\\.org\\.$'
//! ```

use crate::plugin::{Controller, Request};
use anyhow::{anyhow, bail, Result};
use ipnet::IpNet;
use regex::Regex;
use std::sync::Arc;

// ------------------------------------------------------------------ lexer

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64),
    Str(String),
    Ident(String),
    Op(String),
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Eof,
}

fn lex(s: &str) -> Result<Vec<Tok>> {
    let cs: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < cs.len() {
        let c = cs[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '[' => {
                out.push(Tok::LBracket);
                i += 1;
            }
            ']' => {
                out.push(Tok::RBracket);
                i += 1;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            '\'' | '"' => {
                let q = c;
                i += 1;
                let mut v = String::new();
                while i < cs.len() && cs[i] != q {
                    if cs[i] == '\\' && i + 1 < cs.len() {
                        i += 1;
                        v.push(match cs[i] {
                            'n' => '\n',
                            't' => '\t',
                            o => o,
                        });
                    } else {
                        v.push(cs[i]);
                    }
                    i += 1;
                }
                if i >= cs.len() {
                    bail!("unterminated string");
                }
                i += 1;
                out.push(Tok::Str(v));
            }
            '0'..='9' => {
                let st = i;
                while i < cs.len() && (cs[i].is_ascii_digit() || cs[i] == '.') {
                    i += 1;
                }
                let t: String = cs[st..i].iter().collect();
                out.push(Tok::Num(t.parse().map_err(|_| anyhow!("bad number {}", t))?));
            }
            _ if c.is_alphabetic() || c == '_' => {
                let st = i;
                while i < cs.len() && (cs[i].is_alphanumeric() || cs[i] == '_' || cs[i] == '.') {
                    i += 1;
                }
                let t: String = cs[st..i].iter().collect();
                match t.as_str() {
                    "and" => out.push(Tok::Op("&&".into())),
                    "or" => out.push(Tok::Op("||".into())),
                    "not" => out.push(Tok::Op("!".into())),
                    "in" | "matches" | "contains" | "startsWith" | "endsWith" => out.push(Tok::Op(t)),
                    _ => out.push(Tok::Ident(t)),
                }
            }
            _ => {
                let two: String = cs[i..(i + 2).min(cs.len())].iter().collect();
                let op = match two.as_str() {
                    "==" | "!=" | "<=" | ">=" | "&&" | "||" => two.clone(),
                    _ => match c {
                        '<' | '>' | '!' | '+' | '-' | '*' | '/' | '%' => c.to_string(),
                        _ => bail!("unexpected character '{}'", c),
                    },
                };
                i += op.len();
                out.push(Tok::Op(op));
            }
        }
    }
    out.push(Tok::Eof);
    Ok(out)
}

// ------------------------------------------------------------------ AST

#[derive(Debug, Clone)]
enum Expr {
    Num(f64),
    Str(String),
    Bool(bool),
    List(Vec<Expr>),
    Call(String, Vec<Expr>),
    Unary(String, Box<Expr>),
    Binary(String, Box<Expr>, Box<Expr>),
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

fn prec(op: &str) -> u8 {
    match op {
        "||" => 1,
        "&&" => 2,
        "==" | "!=" | "<" | ">" | "<=" | ">=" | "in" | "matches" | "contains" | "startsWith" | "endsWith" => 3,
        "+" | "-" => 4,
        "*" | "/" | "%" => 5,
        _ => 0,
    }
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.pos]
    }
    fn next(&mut self) -> Tok {
        let t = self.toks[self.pos].clone();
        if self.pos + 1 < self.toks.len() {
            self.pos += 1;
        }
        t
    }
    fn expect(&mut self, t: Tok) -> Result<()> {
        let n = self.next();
        if n != t {
            bail!("expected {:?}, got {:?}", t, n);
        }
        Ok(())
    }

    fn parse_expr(&mut self, min_prec: u8) -> Result<Expr> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Tok::Op(o) if prec(o) >= min_prec && prec(o) > 0 => o.clone(),
                _ => break,
            };
            self.next();
            let rhs = self.parse_expr(prec(&op) + 1)?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        match self.peek().clone() {
            Tok::Op(o) if o == "!" || o == "-" => {
                self.next();
                let e = self.parse_unary()?;
                Ok(Expr::Unary(o, Box::new(e)))
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        match self.next() {
            Tok::Num(n) => Ok(Expr::Num(n)),
            Tok::Str(s) => Ok(Expr::Str(s)),
            Tok::LParen => {
                let e = self.parse_expr(1)?;
                self.expect(Tok::RParen)?;
                Ok(e)
            }
            Tok::LBracket => {
                let mut items = Vec::new();
                if *self.peek() != Tok::RBracket {
                    loop {
                        items.push(self.parse_expr(1)?);
                        if *self.peek() == Tok::Comma {
                            self.next();
                            continue;
                        }
                        break;
                    }
                }
                self.expect(Tok::RBracket)?;
                Ok(Expr::List(items))
            }
            Tok::Ident(id) => {
                match id.as_str() {
                    "true" => return Ok(Expr::Bool(true)),
                    "false" => return Ok(Expr::Bool(false)),
                    _ => {}
                }
                if *self.peek() == Tok::LParen {
                    self.next();
                    let mut args = Vec::new();
                    if *self.peek() != Tok::RParen {
                        loop {
                            args.push(self.parse_expr(1)?);
                            if *self.peek() == Tok::Comma {
                                self.next();
                                continue;
                            }
                            break;
                        }
                    }
                    self.expect(Tok::RParen)?;
                    Ok(Expr::Call(id, args))
                } else {
                    // bare identifiers are treated as zero-arg calls (e.g. `name`)
                    Ok(Expr::Call(id, Vec::new()))
                }
            }
            t => bail!("unexpected token {:?}", t),
        }
    }
}

pub fn parse(s: &str) -> Result<Expression> {
    let toks = lex(s)?;
    let mut p = Parser { toks, pos: 0 };
    let e = p.parse_expr(1)?;
    if *p.peek() != Tok::Eof {
        bail!("unexpected trailing token {:?}", p.peek());
    }
    // validate function names and precompile regexes
    validate(&e)?;
    Ok(Expression { expr: e })
}

const FUNCS: &[&str] = &[
    "name", "type", "class", "proto", "size", "port", "id", "opcode", "do", "bufsize", "client_ip", "server_ip", "server_port", "metadata", "incidr",
];

fn validate(e: &Expr) -> Result<()> {
    match e {
        Expr::Call(f, args) => {
            if !FUNCS.contains(&f.as_str()) {
                bail!("unknown function {}", f);
            }
            for a in args {
                validate(a)?;
            }
        }
        Expr::Unary(_, a) => validate(a)?,
        Expr::Binary(op, a, b) => {
            if op == "matches" {
                if let Expr::Str(s) = &**b {
                    Regex::new(s).map_err(|e| anyhow!("bad regex {}: {}", s, e))?;
                }
            }
            validate(a)?;
            validate(b)?;
        }
        Expr::List(items) => {
            for i in items {
                validate(i)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// ------------------------------------------------------------------ eval

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Num(f64),
    Str(String),
    Bool(bool),
    List(Vec<Value>),
}

impl Value {
    fn truthy(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Num(n) => *n != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::List(l) => !l.is_empty(),
        }
    }
    fn as_str(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Num(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::List(_) => String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Expression {
    expr: Expr,
}

impl Expression {
    pub fn eval(&self, req: &Request) -> bool {
        eval(&self.expr, req).map(|v| v.truthy()).unwrap_or(false)
    }
}

fn eval(e: &Expr, req: &Request) -> Result<Value> {
    Ok(match e {
        Expr::Num(n) => Value::Num(*n),
        Expr::Str(s) => Value::Str(s.clone()),
        Expr::Bool(b) => Value::Bool(*b),
        Expr::List(items) => Value::List(items.iter().map(|i| eval(i, req)).collect::<Result<_>>()?),
        Expr::Unary(op, a) => {
            let v = eval(a, req)?;
            match op.as_str() {
                "!" => Value::Bool(!v.truthy()),
                "-" => match v {
                    Value::Num(n) => Value::Num(-n),
                    _ => bail!("unary minus on non-number"),
                },
                _ => bail!("bad unary op"),
            }
        }
        Expr::Binary(op, a, b) => {
            match op.as_str() {
                "&&" => return Ok(Value::Bool(eval(a, req)?.truthy() && eval(b, req)?.truthy())),
                "||" => return Ok(Value::Bool(eval(a, req)?.truthy() || eval(b, req)?.truthy())),
                _ => {}
            }
            let l = eval(a, req)?;
            let r = eval(b, req)?;
            match op.as_str() {
                "==" => Value::Bool(l == r),
                "!=" => Value::Bool(l != r),
                "<" | ">" | "<=" | ">=" => {
                    let (x, y) = match (&l, &r) {
                        (Value::Num(x), Value::Num(y)) => (*x, *y),
                        _ => bail!("comparison on non-numbers"),
                    };
                    Value::Bool(match op.as_str() {
                        "<" => x < y,
                        ">" => x > y,
                        "<=" => x <= y,
                        _ => x >= y,
                    })
                }
                "+" | "-" | "*" | "/" | "%" => match (&l, &r) {
                    (Value::Num(x), Value::Num(y)) => Value::Num(match op.as_str() {
                        "+" => x + y,
                        "-" => x - y,
                        "*" => x * y,
                        "/" => x / y,
                        _ => x % y,
                    }),
                    (Value::Str(x), Value::Str(y)) if op == "+" => Value::Str(format!("{}{}", x, y)),
                    _ => bail!("arithmetic on non-numbers"),
                },
                "in" => match r {
                    Value::List(items) => Value::Bool(items.contains(&l)),
                    Value::Str(s) => Value::Bool(s.contains(&l.as_str())),
                    _ => bail!("'in' needs a list"),
                },
                "matches" => Value::Bool(Regex::new(&r.as_str()).map(|re| re.is_match(&l.as_str())).unwrap_or(false)),
                "contains" => Value::Bool(l.as_str().contains(&r.as_str())),
                "startsWith" => Value::Bool(l.as_str().starts_with(&r.as_str())),
                "endsWith" => Value::Bool(l.as_str().ends_with(&r.as_str())),
                _ => bail!("bad op {}", op),
            }
        }
        Expr::Call(f, args) => {
            let argv: Vec<Value> = args.iter().map(|a| eval(a, req)).collect::<Result<_>>()?;
            match f.as_str() {
                "name" => Value::Str(req.name_uncached()),
                "type" => Value::Str(req.type_str()),
                "class" => Value::Str(req.class_str()),
                "proto" => Value::Str(req.proto_str().to_string()),
                "size" => Value::Num(req.len() as f64),
                "port" => Value::Num(req.port() as f64),
                "id" => Value::Num(req.msg.id() as f64),
                "opcode" => Value::Num(u8::from(req.msg.op_code()) as f64),
                "do" => Value::Bool(req.do_bit()),
                "bufsize" => Value::Num(req.size() as f64),
                "client_ip" => Value::Str(req.ip().to_string()),
                "server_ip" => Value::Str(req.local_ip().to_string()),
                "server_port" => Value::Num(req.local_port() as f64),
                "metadata" => {
                    let label = argv.first().map(|v| v.as_str()).unwrap_or_default();
                    Value::Str(req.metadata.value(&label).unwrap_or_default())
                }
                "incidr" => {
                    let ip = argv.first().map(|v| v.as_str()).unwrap_or_default();
                    let cidr = argv.get(1).map(|v| v.as_str()).unwrap_or_default();
                    let ip: std::net::IpAddr = ip.parse().map_err(|_| anyhow!("incidr: bad ip {}", ip))?;
                    let net: IpNet = cidr.parse().map_err(|_| anyhow!("incidr: bad cidr {}", cidr))?;
                    Value::Bool(net.contains(&ip))
                }
                _ => bail!("unknown function {}", f),
            }
        }
    })
}

pub fn setup(c: &mut Controller<'_>) -> anyhow::Result<()> {
    let mut n = 0;
    while c.next() {
        n += 1;
        if n > 1 {
            return Err(c.errf("plugin/view: this plugin can only be used once per Server Block"));
        }
        let args = c.remaining_args_until_brace();
        if args.len() != 1 {
            return Err(c.arg_err());
        }
        let name = args[0].clone();
        let mut exprs: Vec<Expression> = Vec::new();
        while c.next_block() {
            match c.val() {
                "expr" => {
                    let a = c.remaining_args();
                    if a.is_empty() {
                        return Err(c.arg_err());
                    }
                    let text = a.join(" ");
                    exprs.push(parse(&text).map_err(|e| c.errf(format!("expr {}: {}", text, e)))?);
                }
                o => return Err(c.errf(format!("unknown property '{}'", o))),
            }
        }
        if exprs.is_empty() {
            return Err(c.errf("at least one expr is required"));
        }
        let exprs = Arc::new(exprs);
        c.config.view_name = name;
        c.config.filter = Some(Arc::new(move |req: &Request| exprs.iter().all(|e| e.eval(req))));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::RecordType;

    fn req() -> Request {
        Request::for_test("www.example.org.", RecordType::A)
    }

    #[test]
    fn expressions() {
        let r = req();
        assert!(parse("name() == 'www.example.org.'").unwrap().eval(&r));
        assert!(parse("type() in ['A', 'AAAA'] && incidr(client_ip(), '127.0.0.0/8')").unwrap().eval(&r));
        assert!(parse("name() endsWith '.org.'").unwrap().eval(&r));
        assert!(parse("name() matches '^www\\\\.'").unwrap().eval(&r));
        assert!(!parse("port() == 53").unwrap().eval(&r));
        assert!(parse("not (port() == 53) or false").unwrap().eval(&r));
        assert!(parse("proto() == 'udp' and size() > 10").unwrap().eval(&r));
        assert!(parse("nope()").is_err());
    }
}
