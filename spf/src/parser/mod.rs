//! SPF record AST parsing.

// NOTE: `parser::parser` reads awkwardly, but renaming the module would
// churn every import; the lint is allowed rather than restructured.
/// SPF record AST parsing.
#[allow(clippy::module_inception)]
pub mod parser;
