//! Faithful port of `github.com/ganigeorgiev/fexpr@v0.6.0`.
//!
//! PocketBase's filter/rule grammar is defined by this package, and the API
//! exposes its scanner/parser error strings verbatim (wrapped by
//! `tools/search/filter.go`). Keeping this a 1:1 port is therefore part of the
//! compatibility contract, not an implementation detail.

use std::fmt;

/// `fexpr.ErrEmpty`.
pub const ERR_EMPTY: &str = "empty filter expression";
/// `fexpr.ErrIncomplete`.
pub const ERR_INCOMPLETE: &str = "invalid or incomplete filter expression";
/// `fexpr.ErrInvalidComment`.
pub const ERR_INVALID_COMMENT: &str = "invalid comment";

const EOF: char = '\0';

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TokenType {
    /// Go's zero value (used by the parser's `Expr.IsZero` check).
    #[default]
    Zero,
    Unexpected,
    Eof,
    Ws,
    Join,
    Sign,
    Identifier,
    Function,
    Number,
    Text,
    Group,
    Comment,
}

impl TokenType {
    fn as_str(self) -> &'static str {
        match self {
            TokenType::Zero => "",
            TokenType::Unexpected => "unexpected",
            TokenType::Eof => "eof",
            TokenType::Ws => "whitespace",
            TokenType::Join => "join",
            TokenType::Sign => "sign",
            TokenType::Identifier => "identifier",
            TokenType::Function => "function",
            TokenType::Number => "number",
            TokenType::Text => "text",
            TokenType::Group => "group",
            TokenType::Comment => "comment",
        }
    }
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single scanned literal (one or more combined runes).
#[derive(Clone, Debug, Default)]
pub struct Token {
    pub ty: TokenType,
    pub literal: String,
    /// Function arguments (`fexpr.Token.Meta` for `TokenFunction`).
    pub meta: Vec<Token>,
}

impl Token {
    fn is_zero(&self) -> bool {
        self.ty == TokenType::Zero && self.literal.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinOp {
    And,
    Or,
}

#[derive(Clone, Debug)]
pub enum GroupItem {
    Expr(Expr),
    Groups(Vec<ExprGroup>),
}

/// A wrapped expression and its join type.
#[derive(Clone, Debug)]
pub struct ExprGroup {
    pub item: GroupItem,
    pub join: JoinOp,
}

/// An individual tokenized expression: left operand, operator, right operand.
#[derive(Clone, Debug)]
pub struct Expr {
    pub left: Token,
    pub op: String,
    pub right: Token,
}

/// A scanner failure, carrying the token literal scanned so far (Go's scan
/// functions always return the token alongside the error).
type ScanResult = Result<Token, (Token, String)>;

fn is_whitespace(ch: char) -> bool {
    ch == ' ' || ch == '\t' || ch == '\n'
}

fn is_letter(ch: char) -> bool {
    ch.is_ascii_lowercase() || ch.is_ascii_uppercase()
}

fn is_digit(ch: char) -> bool {
    ch.is_ascii_digit()
}

fn is_text_start(ch: char) -> bool {
    ch == '\'' || ch == '"'
}

fn is_number_start(ch: char) -> bool {
    ch == '-' || is_digit(ch)
}

fn is_sign_start(ch: char) -> bool {
    matches!(ch, '=' | '?' | '!' | '>' | '<' | '~')
}

fn is_join_start(ch: char) -> bool {
    ch == '&' || ch == '|'
}

fn is_group_start(ch: char) -> bool {
    ch == '('
}

fn is_comment_start(ch: char) -> bool {
    ch == '/'
}

fn is_identifier_special_start(ch: char) -> bool {
    matches!(ch, '@' | '_' | '#')
}

fn is_identifier_start(ch: char) -> bool {
    is_letter(ch) || is_identifier_special_start(ch)
}

fn is_identifier_combine(ch: char) -> bool {
    ch == '.' || ch == ':'
}

fn is_sign_operator(literal: &str) -> bool {
    matches!(
        literal,
        "=" | "!=" | "~" | "!~" | "<" | "<=" | ">" | ">=" | "?=" | "?!=" | "?~" | "?!~" | "?<"
            | "?<=" | "?>" | "?>="
    )
}

fn is_join_operator(literal: &str) -> bool {
    literal == "&&" || literal == "||"
}

fn is_valid_identifier(literal: &str) -> bool {
    let Some(last) = literal.chars().last() else {
        return false;
    };
    !is_identifier_combine(last)
        && !(literal.chars().count() == 1
            && literal.chars().next().is_some_and(is_identifier_special_start))
}

/// Go's `%q` for a rune (single quotes).
fn go_quote_rune(ch: char) -> String {
    let mut out = String::from("'");
    match ch {
        '\'' => out.push_str("\\'"),
        '"' => out.push_str("\\\""),
        '\\' => out.push_str("\\\\"),
        '\x07' => out.push_str("\\a"),
        '\x08' => out.push_str("\\b"),
        '\x0c' => out.push_str("\\f"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        '\x0b' => out.push_str("\\v"),
        ' ' => out.push(' '),
        c if c.is_ascii_graphic() => out.push(c),
        c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
        c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
        c => out.push_str(&format!("\\U{:08x}", c as u32)),
    }
    out.push('\'');
    out
}

fn go_quote(value: &str) -> String {
    crate::fields::go_quote(value)
}

/// Scanner for the `fexpr` grammar.
struct Scanner {
    chars: Vec<char>,
    pos: usize,
    last_rune_size: isize,
    max_func_depth: usize,
}

impl Scanner {
    fn new(data: &str) -> Self {
        Self {
            chars: data.chars().collect(),
            pos: 0,
            last_rune_size: -1,
            max_func_depth: 3,
        }
    }

    fn scan(&mut self) -> Result<Token, String> {
        let ch = self.read();

        if ch == EOF {
            return Ok(Token {
                ty: TokenType::Eof,
                ..Default::default()
            });
        }

        if is_whitespace(ch) {
            self.unread_once();
            return self.scan_whitespace();
        }
        if is_group_start(ch) {
            self.unread_once();
            return self.scan_group().map_err(|(_, e)| e);
        }
        if is_identifier_start(ch) {
            self.unread_once();
            return self.scan_identifier(self.max_func_depth).map_err(|(_, e)| e);
        }
        if is_number_start(ch) {
            self.unread_once();
            return self.scan_number().map_err(|(_, e)| e);
        }
        if is_text_start(ch) {
            self.unread_once();
            return self.scan_text(false).map_err(|(_, e)| e);
        }
        if is_sign_start(ch) {
            self.unread_once();
            return self.scan_sign().map_err(|(_, e)| e);
        }
        if is_join_start(ch) {
            self.unread_once();
            return self.scan_join().map_err(|(_, e)| e);
        }
        if is_comment_start(ch) {
            self.unread_once();
            return self.scan_comment().map_err(|(_, e)| e);
        }

        Err(format!("unexpected character {}", go_quote_rune(ch)))
    }

    fn scan_whitespace(&mut self) -> Result<Token, String> {
        let mut buf = String::new();
        loop {
            let ch = self.read();
            if ch == EOF {
                break;
            }
            if !is_whitespace(ch) {
                self.unread_once();
                break;
            }
            buf.push(ch);
        }
        Ok(Token {
            ty: TokenType::Ws,
            literal: buf,
            ..Default::default()
        })
    }

    fn scan_number(&mut self) -> ScanResult {
        let mut buf = String::new();
        let mut had_dot = false;

        loop {
            let ch = self.read();
            if ch == EOF {
                break;
            }
            if !is_digit(ch) && (ch != '-' || !buf.is_empty()) && (ch != '.' || had_dot) {
                self.unread_once();
                break;
            }
            buf.push(ch);
            if ch == '.' {
                had_dot = true;
            }
        }

        let literal = buf;
        let token = Token {
            ty: TokenType::Number,
            literal: literal.clone(),
            ..Default::default()
        };
        let bytes = literal.as_bytes();
        if (bytes.len() == 1 && bytes[0] == b'-')
            || bytes.first() == Some(&b'.')
            || bytes.last() == Some(&b'.')
        {
            return Err((token, format!("invalid number {}", go_quote(&literal))));
        }
        Ok(token)
    }

    fn scan_text(&mut self, preserve_quotes: bool) -> ScanResult {
        let mut buf = String::new();
        let first_ch = self.read();
        if preserve_quotes {
            buf.push(first_ch);
        }

        let mut escape_next = false;
        let mut has_matching_quotes = false;

        loop {
            let ch = self.read();
            if ch == EOF {
                break;
            }
            if escape_next {
                escape_next = false;
                if !preserve_quotes {
                    match ch {
                        'n' => buf.push('\n'),
                        't' => buf.push('\t'),
                        'r' => buf.push('\r'),
                        '\\' | '\'' | '"' => buf.push(ch),
                        _ => {
                            buf.push('\\');
                            buf.push(ch);
                        }
                    }
                } else {
                    buf.push(ch);
                }
            } else if ch == '\\' {
                escape_next = true;
                if preserve_quotes {
                    buf.push(ch);
                }
            } else if ch == first_ch {
                has_matching_quotes = true;
                if preserve_quotes {
                    buf.push(ch);
                }
                break;
            } else {
                buf.push(ch);
            }
        }

        let mut literal = buf;
        let mut err = None;
        if !has_matching_quotes {
            if !preserve_quotes {
                literal = format!("{first_ch}{literal}");
            }
            err = Some(format!("invalid quoted text {}", go_quote(&literal)));
        }

        let token = Token {
            ty: TokenType::Text,
            literal,
            ..Default::default()
        };
        match err {
            Some(e) => Err((token, e)),
            None => Ok(token),
        }
    }

    fn scan_comment(&mut self) -> ScanResult {
        let mut buf = String::new();
        if !is_comment_start(self.read()) || !is_comment_start(self.read()) {
            return Err((
                Token {
                    ty: TokenType::Comment,
                    ..Default::default()
                },
                ERR_INVALID_COMMENT.to_string(),
            ));
        }
        loop {
            let ch = self.read();
            if ch == EOF || ch == '\n' {
                break;
            }
            buf.push(ch);
        }
        Ok(Token {
            ty: TokenType::Comment,
            literal: buf.trim().to_string(),
            ..Default::default()
        })
    }

    fn scan_identifier(&mut self, func_depth: usize) -> ScanResult {
        let mut buf = String::new();
        buf.push(self.read());

        loop {
            let ch = self.read();
            if ch == EOF {
                break;
            }
            if ch == '(' {
                let func_name = buf;
                let token = Token {
                    ty: TokenType::Function,
                    literal: func_name.clone(),
                    ..Default::default()
                };
                if func_depth == 0 {
                    return Err((
                        token,
                        format!(
                            "max nested function arguments reached (max: {})",
                            self.max_func_depth
                        ),
                    ));
                }
                if !is_valid_identifier(&func_name) {
                    return Err((
                        token,
                        format!("invalid function name {}", go_quote(&func_name)),
                    ));
                }
                self.unread_once();
                return self.scan_function_args(&func_name, func_depth);
            }
            if !is_letter(ch) && !is_digit(ch) && !is_identifier_combine(ch) && ch != '_' {
                self.unread_once();
                break;
            }
            buf.push(ch);
        }

        let literal = buf;
        let token = Token {
            ty: TokenType::Identifier,
            literal: literal.clone(),
            ..Default::default()
        };
        if !is_valid_identifier(&literal) {
            return Err((token, format!("invalid identifier {}", go_quote(&literal))));
        }
        Ok(token)
    }

    fn scan_function_args(&mut self, func_name: &str, func_depth: usize) -> ScanResult {
        let mut args: Vec<Token> = Vec::new();
        let mut expect_comma = false;

        let ch = self.read();
        if ch != '(' {
            return Err((
                Token {
                    ty: TokenType::Function,
                    literal: func_name.to_string(),
                    ..Default::default()
                },
                format!(
                    "invalid or incomplete function call {}",
                    go_quote(func_name)
                ),
            ));
        }

        let mut is_closed = false;
        loop {
            let ch = self.read();
            if ch == EOF {
                break;
            }
            if ch == ')' {
                is_closed = true;
                break;
            }

            if is_whitespace(ch) {
                if let Err(e) = self.scan_whitespace() {
                    return Err((
                        Token {
                            ty: TokenType::Function,
                            literal: func_name.to_string(),
                            meta: args,
                        },
                        format!(
                            "failed to scan whitespaces in function {}: {e}",
                            go_quote(func_name)
                        ),
                    ));
                }
                continue;
            }

            if is_comment_start(ch) {
                self.unread_once();
                if let Err((_, e)) = self.scan_comment() {
                    return Err((
                        Token {
                            ty: TokenType::Function,
                            literal: func_name.to_string(),
                            meta: args,
                        },
                        format!(
                            "failed to scan comment in function {}: {e}",
                            go_quote(func_name)
                        ),
                    ));
                }
                continue;
            }

            let is_comma = ch == ',';

            if expect_comma && !is_comma {
                return Err((
                    Token {
                        ty: TokenType::Function,
                        literal: func_name.to_string(),
                        meta: args,
                    },
                    format!(
                        "expected comma after the last argument in function {}",
                        go_quote(func_name)
                    ),
                ));
            }
            if !expect_comma && is_comma {
                return Err((
                    Token {
                        ty: TokenType::Function,
                        literal: func_name.to_string(),
                        meta: args,
                    },
                    format!("unexpected comma in function {}", go_quote(func_name)),
                ));
            }

            expect_comma = false;

            if is_comma {
                continue;
            }

            if is_identifier_start(ch) {
                self.unread_once();
                match self.scan_identifier(func_depth - 1) {
                    Ok(t) => args.push(t),
                    Err((t, e)) => {
                        return Err((
                            Token {
                                ty: TokenType::Function,
                                literal: func_name.to_string(),
                                meta: args,
                            },
                            format!(
                                "invalid identifier argument {} in function {}: {e}",
                                go_quote(&t.literal),
                                go_quote(func_name)
                            ),
                        ))
                    }
                }
                expect_comma = true;
            } else if is_number_start(ch) {
                self.unread_once();
                match self.scan_number() {
                    Ok(t) => args.push(t),
                    Err((t, e)) => {
                        return Err((
                            Token {
                                ty: TokenType::Function,
                                literal: func_name.to_string(),
                                meta: args,
                            },
                            format!(
                                "invalid number argument {} in function {}: {e}",
                                go_quote(&t.literal),
                                go_quote(func_name)
                            ),
                        ))
                    }
                }
                expect_comma = true;
            } else if is_text_start(ch) {
                self.unread_once();
                match self.scan_text(false) {
                    Ok(t) => args.push(t),
                    Err((t, e)) => {
                        return Err((
                            Token {
                                ty: TokenType::Function,
                                literal: func_name.to_string(),
                                meta: args,
                            },
                            format!(
                                "invalid text argument {} in function {}: {e}",
                                go_quote(&t.literal),
                                go_quote(func_name)
                            ),
                        ))
                    }
                }
                expect_comma = true;
            } else {
                return Err((
                    Token {
                        ty: TokenType::Function,
                        literal: func_name.to_string(),
                        meta: args,
                    },
                    format!(
                        "unsupported argument character {} in function {}",
                        go_quote_rune(ch),
                        go_quote(func_name)
                    ),
                ));
            }
        }

        let token = Token {
            ty: TokenType::Function,
            literal: func_name.to_string(),
            meta: args,
        };
        if !is_closed {
            return Err((
                token,
                format!(
                    "invalid or incomplete function {} (expected ')')",
                    go_quote(func_name)
                ),
            ));
        }

        Ok(token)
    }

    fn scan_sign(&mut self) -> ScanResult {
        let mut buf = String::new();
        loop {
            let ch = self.read();
            if ch == EOF {
                break;
            }
            if !is_sign_start(ch) {
                self.unread_once();
                break;
            }
            buf.push(ch);
        }
        let token = Token {
            ty: TokenType::Sign,
            literal: buf.clone(),
            ..Default::default()
        };
        if !is_sign_operator(&buf) {
            return Err((token, format!("invalid sign operator {}", go_quote(&buf))));
        }
        Ok(token)
    }

    fn scan_join(&mut self) -> ScanResult {
        let mut buf = String::new();
        loop {
            let ch = self.read();
            if ch == EOF {
                break;
            }
            if !is_join_start(ch) {
                self.unread_once();
                break;
            }
            buf.push(ch);
        }
        let token = Token {
            ty: TokenType::Join,
            literal: buf.clone(),
            ..Default::default()
        };
        if !is_join_operator(&buf) {
            return Err((token, format!("invalid join operator {}", go_quote(&buf))));
        }
        Ok(token)
    }

    fn scan_group(&mut self) -> ScanResult {
        let mut buf = String::new();
        let first_char = self.read();
        let mut open_groups: i32 = 1;

        loop {
            let ch = self.read();
            if ch == EOF {
                break;
            }
            if is_group_start(ch) {
                open_groups += 1;
                buf.push(ch);
            } else if is_text_start(ch) {
                self.unread_once();
                match self.scan_text(true) {
                    Ok(t) => buf.push_str(&t.literal),
                    Err((t, e)) => {
                        // The errored literal is written as it is.
                        buf.push_str(&t.literal);
                        return Err((
                            Token {
                                ty: TokenType::Group,
                                literal: buf,
                                ..Default::default()
                            },
                            e,
                        ));
                    }
                }
            } else if ch == ')' {
                open_groups -= 1;
                if open_groups <= 0 {
                    break;
                }
                buf.push(ch);
            } else {
                buf.push(ch);
            }
        }

        let token = Token {
            ty: TokenType::Group,
            literal: buf.clone(),
            ..Default::default()
        };
        if !is_group_start(first_char) || open_groups > 0 {
            return Err((
                token,
                format!("invalid formatted group - missing {open_groups} closing bracket(s)"),
            ));
        }
        Ok(token)
    }

    fn unread_once(&mut self) {
        if self.last_rune_size < 0 || (self.pos as isize) < self.last_rune_size {
            return;
        }
        self.pos -= self.last_rune_size as usize;
        self.last_rune_size = -1;
    }

    fn read(&mut self) -> char {
        if self.pos >= self.chars.len() {
            self.last_rune_size = -1;
            return EOF;
        }
        let ch = self.chars[self.pos];
        self.last_rune_size = 1;
        self.pos += 1;
        ch
    }
}

/// Parse the provided text and return its AST as a list of expression groups.
pub fn parse(text: &str) -> Result<Vec<ExprGroup>, String> {
    let mut result: Vec<ExprGroup> = Vec::new();
    let mut scanner = Scanner::new(text);
    let mut step = Step::BeforeSign;
    let mut join = JoinOp::And;
    let mut expr = Expr {
        left: Token::default(),
        op: String::new(),
        right: Token::default(),
    };

    loop {
        let t = scanner.scan()?;

        if t.ty == TokenType::Eof {
            break;
        }
        if t.ty == TokenType::Ws || t.ty == TokenType::Comment {
            continue;
        }

        if t.ty == TokenType::Group {
            let group_result = parse(&t.literal)?;
            if !group_result.is_empty() {
                result.push(ExprGroup {
                    join,
                    item: GroupItem::Groups(group_result),
                });
            }
            step = Step::Join;
            continue;
        }

        match step {
            Step::BeforeSign => {
                if !matches!(
                    t.ty,
                    TokenType::Identifier
                        | TokenType::Text
                        | TokenType::Number
                        | TokenType::Function
                ) {
                    return Err(format!(
                        "expected left operand (identifier, function, text or number), got {} ({})",
                        go_quote(&t.literal),
                        t.ty
                    ));
                }
                expr = Expr {
                    left: t,
                    op: String::new(),
                    right: Token::default(),
                };
                step = Step::Sign;
            }
            Step::Sign => {
                if t.ty != TokenType::Sign {
                    return Err(format!(
                        "expected a sign operator, got {} ({})",
                        go_quote(&t.literal),
                        t.ty
                    ));
                }
                expr.op = t.literal;
                step = Step::AfterSign;
            }
            Step::AfterSign => {
                if !matches!(
                    t.ty,
                    TokenType::Identifier
                        | TokenType::Text
                        | TokenType::Number
                        | TokenType::Function
                ) {
                    return Err(format!(
                        "expected right operand (identifier, function text or number), got {} ({})",
                        go_quote(&t.literal),
                        t.ty
                    ));
                }
                expr.right = t;
                result.push(ExprGroup {
                    join,
                    item: GroupItem::Expr(expr.clone()),
                });
                step = Step::Join;
            }
            Step::Join => {
                if t.ty != TokenType::Join {
                    return Err(format!(
                        "expected && or ||, got {} ({})",
                        go_quote(&t.literal),
                        t.ty
                    ));
                }
                join = if t.literal == "||" {
                    JoinOp::Or
                } else {
                    JoinOp::And
                };
                step = Step::BeforeSign;
            }
        }
    }

    if step != Step::Join {
        if result.is_empty() && expr.left.is_zero() && expr.op.is_empty() && expr.right.is_zero()
        {
            return Err(ERR_EMPTY.to_string());
        }
        return Err(ERR_INCOMPLETE.to_string());
    }

    Ok(result)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    BeforeSign,
    Sign,
    AfterSign,
    Join,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(text: &str) -> String {
        parse(text).unwrap_err()
    }

    #[test]
    fn scanner_and_parser_error_strings_match_fexpr() {
        assert_eq!(err(""), ERR_EMPTY);
        assert_eq!(err("foo"), ERR_INCOMPLETE);
        assert_eq!(err("title ="), ERR_INCOMPLETE);
        assert_eq!(err("title === \"x\""), "invalid sign operator \"===\"");
        assert_eq!(err("title >< 1"), "invalid sign operator \"><\"");
        assert_eq!(
            err("(title = 1"),
            "invalid formatted group - missing 1 closing bracket(s)"
        );
        assert_eq!(err("title = 1)"), "unexpected character ')'");
        assert_eq!(err("title = 1 /* x */"), ERR_INVALID_COMMENT);
        assert_eq!(
            err("title = 1 &&&& title = 2"),
            "invalid join operator \"&&&&\""
        );
        assert_eq!(err("title = -"), "invalid number \"-\"");
        assert_eq!(err("title = .5"), "unexpected character '.'");
        assert_eq!(
            err("title = 'unterminated"),
            "invalid quoted text \"'unterminated\""
        );
        assert_eq!(
            err("title = \"unterminated"),
            "invalid quoted text \"\\\"unterminated\""
        );
        assert_eq!(err("!(title = 1)"), "invalid sign operator \"!\"");
        assert_eq!(
            err("lower(title = 1) = 'x'"),
            "expected comma after the last argument in function \"lower\""
        );
        assert_eq!(err("()"), ERR_EMPTY);
    }

    #[test]
    fn parses_groups_and_joins() {
        let groups = parse("title = 'a' && (title = 'b' || title = 'c')").unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].join, JoinOp::And);
        assert_eq!(groups[1].join, JoinOp::And);
        assert!(matches!(groups[1].item, GroupItem::Groups(_)));
    }
}
