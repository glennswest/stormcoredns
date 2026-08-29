//! Corefile (Caddyfile v1) support: lexer, parser, and the `Dispenser`
//! token cursor that plugin setup functions drive.

pub mod dispenser;
pub mod lexer;
pub mod parser;

pub use dispenser::{ConfigError, Dispenser};
pub use lexer::Token;
pub use parser::{parse_file, parse_str, Directive, ServerBlock};
