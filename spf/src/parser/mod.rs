//! SPF record lexing and AST parsing.

// NOTE: `parser::parser` reads awkwardly, but renaming the module would
// churn every import; the lint is allowed rather than restructured.
/// SPF record lexing.
#[allow(clippy::module_inception)]
pub mod lexer;
/// SPF record AST parsing.
#[allow(clippy::module_inception)]
pub mod parser;
