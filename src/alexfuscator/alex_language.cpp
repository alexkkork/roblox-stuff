#include "alexfuscator/alex_language.hpp"

#include <charconv>
#include <cctype>
#include <cstdlib>
#include <stdexcept>
#include <unordered_set>

namespace alex::lang
{
namespace
{

enum class TokenKind
{
    Eof,
    Newline,
    Identifier,
    Number,
    String,
    Interpolation,
    Let,
    Fn,
    If,
    Else,
    While,
    Repeat,
    Until,
    For,
    In,
    Return,
    Break,
    Continue,
    Scope,
    True,
    False,
    Nil,
    And,
    Or,
    Not,
    FloorDiv,
    LeftParen,
    RightParen,
    LeftBrace,
    RightBrace,
    LeftBracket,
    RightBracket,
    Comma,
    Semicolon,
    Dot,
    Colon,
    Hash,
    Ellipsis,
    Assign,
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    Power,
    Concat,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    AddAssign,
    SubtractAssign,
    MultiplyAssign,
    DivideAssign,
    FloorDivAssign,
    ModuloAssign,
    PowerAssign,
    ConcatAssign,
};

struct Token
{
    TokenKind kind = TokenKind::Eof;
    std::string text;
    Span span;
};

class FrontendError final : public std::runtime_error
{
public:
    explicit FrontendError(Diagnostic diagnostic)
        : std::runtime_error(diagnostic.message)
        , diagnostic(std::move(diagnostic))
    {
    }

    Diagnostic diagnostic;
};

class Lexer
{
public:
    explicit Lexer(std::string_view source)
        : source(source)
    {
    }

    std::vector<Token> scan()
    {
        std::vector<Token> tokens;
        while (!atEnd())
        {
            skipHorizontalSpaceAndComments();
            if (atEnd())
                break;

            Position begin = position();
            char value = peek();
            if (value == '\n' || value == '\r')
            {
                consumeNewline();
                tokens.push_back({TokenKind::Newline, "\n", {begin, position()}});
                lineHasCode = false;
                continue;
            }
            if (isIdentifierStart(value))
            {
                tokens.push_back(identifier());
                lineHasCode = true;
                continue;
            }
            if (std::isdigit(static_cast<unsigned char>(value)) || (value == '.' && std::isdigit(static_cast<unsigned char>(peek(1)))))
            {
                tokens.push_back(number());
                lineHasCode = true;
                continue;
            }
            if (value == '\'' || value == '"')
            {
                tokens.push_back(stringLiteral());
                lineHasCode = true;
                continue;
            }
            if (value == '`')
            {
                tokens.push_back(interpolation());
                lineHasCode = true;
                continue;
            }

            advance();
            auto one = [&](TokenKind kind) {
                tokens.push_back({kind, std::string(1, value), {begin, position()}});
                lineHasCode = true;
            };
            auto matched = [&](char expected, TokenKind yes, TokenKind no) {
                if (match(expected))
                    tokens.push_back({yes, std::string(source.substr(begin.offset, cursor - begin.offset)), {begin, position()}});
                else
                    tokens.push_back({no, std::string(1, value), {begin, position()}});
                lineHasCode = true;
            };

            switch (value)
            {
            case '(':
                one(TokenKind::LeftParen);
                break;
            case ')':
                one(TokenKind::RightParen);
                break;
            case '{':
                one(TokenKind::LeftBrace);
                break;
            case '}':
                one(TokenKind::RightBrace);
                break;
            case '[':
                one(TokenKind::LeftBracket);
                break;
            case ']':
                one(TokenKind::RightBracket);
                break;
            case ',':
                one(TokenKind::Comma);
                break;
            case ';':
                one(TokenKind::Semicolon);
                break;
            case ':':
                one(TokenKind::Colon);
                break;
            case '#':
                one(TokenKind::Hash);
                break;
            case '+':
                matched('=', TokenKind::AddAssign, TokenKind::Add);
                break;
            case '-':
                matched('=', TokenKind::SubtractAssign, TokenKind::Subtract);
                break;
            case '*':
                if (match('='))
                    tokens.push_back({TokenKind::MultiplyAssign, "*=", {begin, position()}});
                else
                    one(TokenKind::Multiply);
                break;
            case '/':
                if (match('='))
                    tokens.push_back({TokenKind::DivideAssign, "/=", {begin, position()}});
                else
                    one(TokenKind::Divide);
                break;
            case '%':
                matched('=', TokenKind::ModuloAssign, TokenKind::Modulo);
                break;
            case '^':
                matched('=', TokenKind::PowerAssign, TokenKind::Power);
                break;
            case '=':
                matched('=', TokenKind::Equal, TokenKind::Assign);
                break;
            case '~':
                if (!match('='))
                    fail("unexpected_character", "Token", begin, "expected '=' after '~'");
                tokens.push_back({TokenKind::NotEqual, "~=", {begin, position()}});
                lineHasCode = true;
                break;
            case '<':
                matched('=', TokenKind::LessEqual, TokenKind::Less);
                break;
            case '>':
                matched('=', TokenKind::GreaterEqual, TokenKind::Greater);
                break;
            case '.':
                if (match('.') && match('.'))
                    tokens.push_back({TokenKind::Ellipsis, "...", {begin, position()}});
                else if (cursor >= 2 && source[cursor - 1] == '.' && source[cursor - 2] == '.')
                {
                    if (match('='))
                        tokens.push_back({TokenKind::ConcatAssign, "..=", {begin, position()}});
                    else
                        tokens.push_back({TokenKind::Concat, "..", {begin, position()}});
                }
                else
                    one(TokenKind::Dot);
                lineHasCode = true;
                break;
            default:
                fail("unexpected_character", "Token", begin, "unexpected character in Alex source");
            }
        }
        Position end = position();
        tokens.push_back({TokenKind::Eof, {}, {end, end}});
        return tokens;
    }

private:
    std::string_view source;
    size_t cursor = 0;
    int line = 1;
    int column = 1;
    bool lineHasCode = false;

    bool atEnd() const
    {
        return cursor >= source.size();
    }

    char peek(size_t lookahead = 0) const
    {
        size_t index = cursor + lookahead;
        return index < source.size() ? source[index] : '\0';
    }

    Position position() const
    {
        return {line, column, cursor};
    }

    char advance()
    {
        char value = source[cursor++];
        ++column;
        return value;
    }

    bool match(char value)
    {
        if (peek() != value)
            return false;
        advance();
        return true;
    }

    void consumeNewline()
    {
        if (peek() == '\r')
        {
            advance();
            if (peek() == '\n')
                advance();
        }
        else
            advance();
        ++line;
        column = 1;
    }

    static bool isIdentifierStart(char value)
    {
        return value == '_' || std::isalpha(static_cast<unsigned char>(value));
    }

    static bool isIdentifierContinue(char value)
    {
        return isIdentifierStart(value) || std::isdigit(static_cast<unsigned char>(value));
    }

    [[noreturn]] void fail(std::string code, std::string kind, Position begin, std::string message) const
    {
        throw FrontendError({"lex", std::move(code), std::move(kind), std::move(message), {begin, position()}});
    }

    void skipHorizontalSpaceAndComments()
    {
        for (;;)
        {
            while (peek() == ' ' || peek() == '\t' || peek() == '\f' || peek() == '\v')
                advance();

            if (peek() == '/' && peek(1) == '*' )
            {
                Position begin = position();
                advance();
                advance();
                while (!atEnd() && !(peek() == '*' && peek(1) == '/'))
                {
                    if (peek() == '\n' || peek() == '\r')
                        consumeNewline();
                    else
                        advance();
                }
                if (atEnd())
                    fail("unterminated_comment", "Comment", begin, "unterminated block comment");
                advance();
                advance();
                continue;
            }

            // At the beginning of a logical line, // is a comment. Inside an
            // expression it is Luau floor division; use `div` when whitespace
            // makes an inline comment clearer to readers.
            if (peek() == '/' && peek(1) == '/' && !lineHasCode)
            {
                while (!atEnd() && peek() != '\n' && peek() != '\r')
                    advance();
                continue;
            }
            break;
        }
    }

    Token identifier()
    {
        Position begin = position();
        size_t start = cursor;
        while (isIdentifierContinue(peek()))
            advance();
        std::string text(source.substr(start, cursor - start));
        static const std::unordered_map<std::string, TokenKind> keywords = {
            {"let", TokenKind::Let}, {"fn", TokenKind::Fn}, {"if", TokenKind::If}, {"else", TokenKind::Else},
            {"while", TokenKind::While}, {"repeat", TokenKind::Repeat}, {"until", TokenKind::Until}, {"for", TokenKind::For},
            {"in", TokenKind::In}, {"return", TokenKind::Return}, {"break", TokenKind::Break}, {"continue", TokenKind::Continue},
            {"scope", TokenKind::Scope}, {"true", TokenKind::True}, {"false", TokenKind::False}, {"nil", TokenKind::Nil},
            {"and", TokenKind::And}, {"or", TokenKind::Or}, {"not", TokenKind::Not}, {"div", TokenKind::FloorDiv},
        };
        auto found = keywords.find(text);
        return {found == keywords.end() ? TokenKind::Identifier : found->second, std::move(text), {begin, position()}};
    }

    Token number()
    {
        Position begin = position();
        size_t start = cursor;
        if (peek() == '0' && (peek(1) == 'x' || peek(1) == 'X'))
        {
            advance();
            advance();
            while (std::isxdigit(static_cast<unsigned char>(peek())) || peek() == '_')
                advance();
        }
        else
        {
            while (std::isdigit(static_cast<unsigned char>(peek())) || peek() == '_')
                advance();
            if (peek() == '.' && peek(1) != '.')
            {
                advance();
                while (std::isdigit(static_cast<unsigned char>(peek())) || peek() == '_')
                    advance();
            }
            if (peek() == 'e' || peek() == 'E')
            {
                advance();
                if (peek() == '+' || peek() == '-')
                    advance();
                while (std::isdigit(static_cast<unsigned char>(peek())) || peek() == '_')
                    advance();
            }
        }
        return {TokenKind::Number, std::string(source.substr(start, cursor - start)), {begin, position()}};
    }

    Token stringLiteral()
    {
        Position begin = position();
        char quote = advance();
        std::string value;
        while (!atEnd() && peek() != quote)
        {
            if (peek() == '\n' || peek() == '\r')
                fail("unterminated_string", "String", begin, "quoted strings cannot contain an unescaped newline");
            char current = advance();
            if (current != '\\')
            {
                value.push_back(current);
                continue;
            }
            if (atEnd())
                fail("unterminated_string", "String", begin, "unterminated string escape");
            char escaped = advance();
            switch (escaped)
            {
            case 'n':
                value.push_back('\n');
                break;
            case 'r':
                value.push_back('\r');
                break;
            case 't':
                value.push_back('\t');
                break;
            case '0':
                value.push_back('\0');
                break;
            case '\\':
            case '\'':
            case '"':
                value.push_back(escaped);
                break;
            default:
                value.push_back(escaped);
                break;
            }
        }
        if (!match(quote))
            fail("unterminated_string", "String", begin, "unterminated string literal");
        return {TokenKind::String, std::move(value), {begin, position()}};
    }

    Token interpolation()
    {
        Position begin = position();
        advance();
        std::string value;
        int braceDepth = 0;
        while (!atEnd())
        {
            char current = advance();
            if (current == '`' && braceDepth == 0)
                return {TokenKind::Interpolation, std::move(value), {begin, position()}};
            if (current == '\\' && !atEnd())
            {
                value.push_back(current);
                value.push_back(advance());
                continue;
            }
            if (current == '{')
                ++braceDepth;
            else if (current == '}' && braceDepth > 0)
                --braceDepth;
            if (current == '\n')
            {
                ++line;
                column = 1;
            }
            value.push_back(current);
        }
        fail("unterminated_interpolation", "Interpolation", begin, "unterminated interpolated string");
    }
};

class Parser
{
public:
    explicit Parser(std::vector<Token> tokens)
        : tokens(std::move(tokens))
    {
    }

    Program parseProgram()
    {
        consumeTerminators();
        auto root = std::make_shared<Block>();
        root->span.begin = current().span.begin;
        while (!check(TokenKind::Eof))
        {
            root->statements.push_back(statement());
            requireTerminator();
            consumeTerminators();
        }
        root->span.end = current().span.end;
        return {root};
    }

private:
    std::vector<Token> tokens;
    size_t cursor = 0;

    const Token& current() const
    {
        return tokens.at(cursor);
    }

    const Token& previous() const
    {
        return tokens.at(cursor - 1);
    }

    bool check(TokenKind kind) const
    {
        return current().kind == kind;
    }

    bool match(TokenKind kind)
    {
        if (!check(kind))
            return false;
        ++cursor;
        return true;
    }

    const Token& expect(TokenKind kind, std::string kindName, std::string message)
    {
        if (!check(kind))
            fail("expected_token", std::move(kindName), current().span, std::move(message));
        ++cursor;
        return previous();
    }

    [[noreturn]] void fail(std::string code, std::string kind, Span span, std::string message) const
    {
        throw FrontendError({"parse", std::move(code), std::move(kind), std::move(message), span});
    }

    void consumeTerminators()
    {
        while (match(TokenKind::Newline) || match(TokenKind::Semicolon))
        {
        }
    }

    void requireTerminator()
    {
        if (check(TokenKind::Newline) || check(TokenKind::Semicolon) || check(TokenKind::RightBrace) || check(TokenKind::Eof))
            return;
        fail("expected_statement_end", "Statement", current().span, "expected a newline, semicolon, or closing brace after statement");
    }

    BlockPtr block()
    {
        const Token& open = expect(TokenKind::LeftBrace, "Block", "expected '{' to begin block");
        consumeTerminators();
        auto result = std::make_shared<Block>();
        result->span.begin = open.span.begin;
        while (!check(TokenKind::RightBrace) && !check(TokenKind::Eof))
        {
            result->statements.push_back(statement());
            requireTerminator();
            consumeTerminators();
        }
        const Token& close = expect(TokenKind::RightBrace, "Block", "expected '}' after block");
        result->span.end = close.span.end;
        return result;
    }

    StatementPtr statement()
    {
        if (match(TokenKind::Let))
            return letStatement(previous());
        if (match(TokenKind::Fn) && check(TokenKind::Identifier))
            return functionStatement(previous());
        if (cursor > 0 && previous().kind == TokenKind::Fn && !check(TokenKind::Identifier))
            --cursor;
        if (match(TokenKind::Return))
            return returnStatement(previous());
        if (match(TokenKind::If))
            return ifStatement(previous());
        if (match(TokenKind::While))
            return whileStatement(previous());
        if (match(TokenKind::Repeat))
            return repeatStatement(previous());
        if (match(TokenKind::For))
            return forStatement(previous());
        if (match(TokenKind::Break))
            return simpleStatement(Statement::Kind::Break, previous());
        if (match(TokenKind::Continue))
            return simpleStatement(Statement::Kind::Continue, previous());
        if (match(TokenKind::Scope))
        {
            const Token& begin = previous();
            auto result = simpleStatement(Statement::Kind::Scope, begin);
            result->body = block();
            result->span.end = result->body->span.end;
            return result;
        }
        return expressionOrAssignmentStatement();
    }

    StatementPtr simpleStatement(Statement::Kind kind, const Token& token)
    {
        auto result = std::make_shared<Statement>();
        result->kind = kind;
        result->span = token.span;
        return result;
    }

    StatementPtr letStatement(const Token& begin)
    {
        auto result = simpleStatement(Statement::Kind::Let, begin);
        do
            result->names.push_back(expect(TokenKind::Identifier, "Let", "expected a local name after 'let'").text);
        while (match(TokenKind::Comma));
        if (match(TokenKind::Assign))
            result->values = expressionList();
        result->span.end = result->values.empty() ? previous().span.end : result->values.back()->span.end;
        return result;
    }

    ExprPtr functionExpression(const Token& begin, std::string debugName = {})
    {
        auto result = std::make_shared<Expr>();
        result->kind = Expr::Kind::Function;
        result->span.begin = begin.span.begin;
        result->text = std::move(debugName);
        expect(TokenKind::LeftParen, "Function", "expected '(' after function name");
        if (!check(TokenKind::RightParen))
        {
            do
            {
                if (match(TokenKind::Ellipsis))
                {
                    result->variadic = true;
                    break;
                }
                result->names.push_back(expect(TokenKind::Identifier, "Function", "expected a parameter name").text);
            } while (match(TokenKind::Comma));
        }
        expect(TokenKind::RightParen, "Function", "expected ')' after parameters");
        consumeTerminators();
        result->body = block();
        result->span.end = result->body->span.end;
        return result;
    }

    StatementPtr functionStatement(const Token& begin)
    {
        const Token& name = expect(TokenKind::Identifier, "Function", "expected a function name");
        auto result = simpleStatement(Statement::Kind::Function, begin);
        result->names.push_back(name.text);
        result->values.push_back(functionExpression(begin, name.text));
        result->span.end = result->values.front()->span.end;
        return result;
    }

    StatementPtr returnStatement(const Token& begin)
    {
        auto result = simpleStatement(Statement::Kind::Return, begin);
        if (!check(TokenKind::Newline) && !check(TokenKind::Semicolon) && !check(TokenKind::RightBrace) && !check(TokenKind::Eof))
            result->values = expressionList();
        result->span.end = result->values.empty() ? begin.span.end : result->values.back()->span.end;
        return result;
    }

    StatementPtr ifStatement(const Token& begin)
    {
        auto result = simpleStatement(Statement::Kind::If, begin);
        result->condition = expression();
        consumeTerminators();
        result->body = block();
        consumeTerminators();
        if (match(TokenKind::Else))
        {
            consumeTerminators();
            if (match(TokenKind::If))
            {
                result->elseBody = std::make_shared<Block>();
                result->elseBody->span.begin = previous().span.begin;
                result->elseBody->statements.push_back(ifStatement(previous()));
                result->elseBody->span.end = result->elseBody->statements.back()->span.end;
            }
            else
                result->elseBody = block();
        }
        result->span.end = result->elseBody ? result->elseBody->span.end : result->body->span.end;
        return result;
    }

    StatementPtr whileStatement(const Token& begin)
    {
        auto result = simpleStatement(Statement::Kind::While, begin);
        result->condition = expression();
        consumeTerminators();
        result->body = block();
        result->span.end = result->body->span.end;
        return result;
    }

    StatementPtr repeatStatement(const Token& begin)
    {
        auto result = simpleStatement(Statement::Kind::Repeat, begin);
        consumeTerminators();
        result->body = block();
        consumeTerminators();
        expect(TokenKind::Until, "Repeat", "expected 'until' after repeat block");
        result->condition = expression();
        result->span.end = result->condition->span.end;
        return result;
    }

    StatementPtr forStatement(const Token& begin)
    {
        auto result = simpleStatement(Statement::Kind::ForIn, begin);
        result->names.push_back(expect(TokenKind::Identifier, "For", "expected a loop variable").text);
        if (match(TokenKind::Assign))
        {
            result->kind = Statement::Kind::ForNumeric;
            result->values.push_back(expression());
            expect(TokenKind::Comma, "For", "expected ',' after numeric loop start");
            result->values.push_back(expression());
            if (match(TokenKind::Comma))
                result->values.push_back(expression());
        }
        else
        {
            while (match(TokenKind::Comma))
                result->names.push_back(expect(TokenKind::Identifier, "For", "expected another loop variable").text);
            expect(TokenKind::In, "For", "expected 'in' before iterator expressions");
            result->values = expressionList();
        }
        consumeTerminators();
        result->body = block();
        result->span.end = result->body->span.end;
        return result;
    }

    StatementPtr expressionOrAssignmentStatement()
    {
        ExprPtr first = expression();
        std::vector<ExprPtr> left{first};
        while (match(TokenKind::Comma))
            left.push_back(expression());

        TokenKind kind = current().kind;
        if (kind == TokenKind::Assign)
        {
            ++cursor;
            auto result = std::make_shared<Statement>();
            result->kind = Statement::Kind::Assign;
            result->span.begin = first->span.begin;
            result->targets = std::move(left);
            result->values = expressionList();
            result->span.end = result->values.back()->span.end;
            return result;
        }

        if (isCompound(kind))
        {
            if (left.size() != 1)
                fail("invalid_compound_target", "CompoundAssign", first->span, "compound assignment requires exactly one target");
            Token operation = current();
            ++cursor;
            auto result = std::make_shared<Statement>();
            result->kind = Statement::Kind::CompoundAssign;
            result->span.begin = first->span.begin;
            result->targets = std::move(left);
            result->values.push_back(expression());
            result->text = compoundOperator(operation.kind);
            result->span.end = result->values.front()->span.end;
            return result;
        }

        if (left.size() != 1)
            fail("unexpected_expression_list", "ExpressionStatement", first->span, "an expression statement cannot contain a comma-separated list");
        auto result = std::make_shared<Statement>();
        result->kind = Statement::Kind::Expression;
        result->span = first->span;
        result->values.push_back(std::move(first));
        return result;
    }

    static bool isCompound(TokenKind kind)
    {
        return kind == TokenKind::AddAssign || kind == TokenKind::SubtractAssign || kind == TokenKind::MultiplyAssign || kind == TokenKind::DivideAssign ||
            kind == TokenKind::FloorDivAssign || kind == TokenKind::ModuloAssign || kind == TokenKind::PowerAssign || kind == TokenKind::ConcatAssign;
    }

    static std::string compoundOperator(TokenKind kind)
    {
        switch (kind)
        {
        case TokenKind::AddAssign:
            return "+";
        case TokenKind::SubtractAssign:
            return "-";
        case TokenKind::MultiplyAssign:
            return "*";
        case TokenKind::DivideAssign:
            return "/";
        case TokenKind::FloorDivAssign:
            return "//";
        case TokenKind::ModuloAssign:
            return "%";
        case TokenKind::PowerAssign:
            return "^";
        case TokenKind::ConcatAssign:
            return "..";
        default:
            return {};
        }
    }

    std::vector<ExprPtr> expressionList()
    {
        std::vector<ExprPtr> result;
        do
            result.push_back(expression());
        while (match(TokenKind::Comma));
        return result;
    }

    ExprPtr expression(int minimumPrecedence = 1)
    {
        ExprPtr left = unary();
        for (;;)
        {
            int precedence = binaryPrecedence(current().kind);
            if (precedence < minimumPrecedence)
                break;
            Token operation = current();
            ++cursor;
            int nextMinimum = isRightAssociative(operation.kind) ? precedence : precedence + 1;
            ExprPtr right = expression(nextMinimum);
            auto binary = std::make_shared<Expr>();
            binary->kind = Expr::Kind::Binary;
            binary->span = {left->span.begin, right->span.end};
            binary->text = operationText(operation.kind);
            binary->values = {std::move(left), std::move(right)};
            left = std::move(binary);
        }
        return left;
    }

    ExprPtr unary()
    {
        if (match(TokenKind::Not) || match(TokenKind::Subtract) || match(TokenKind::Hash))
        {
            Token operation = previous();
            ExprPtr value = unary();
            auto result = std::make_shared<Expr>();
            result->kind = Expr::Kind::Unary;
            result->span = {operation.span.begin, value->span.end};
            result->text = operationText(operation.kind);
            result->values.push_back(std::move(value));
            return result;
        }
        return suffix(primary());
    }

    ExprPtr suffix(ExprPtr value)
    {
        for (;;)
        {
            if (match(TokenKind::Dot))
            {
                Token name = expect(TokenKind::Identifier, "IndexName", "expected a field name after '.'");
                auto next = std::make_shared<Expr>();
                next->kind = Expr::Kind::IndexName;
                next->span = {value->span.begin, name.span.end};
                next->text = name.text;
                next->values.push_back(std::move(value));
                value = std::move(next);
            }
            else if (match(TokenKind::LeftBracket))
            {
                ExprPtr key = expression();
                Token close = expect(TokenKind::RightBracket, "Index", "expected ']' after index expression");
                auto next = std::make_shared<Expr>();
                next->kind = Expr::Kind::Index;
                next->span = {value->span.begin, close.span.end};
                next->values = {std::move(value), std::move(key)};
                value = std::move(next);
            }
            else if (match(TokenKind::Colon))
            {
                Token name = expect(TokenKind::Identifier, "MethodCall", "expected a method name after ':'");
                auto next = std::make_shared<Expr>();
                next->kind = Expr::Kind::MethodCall;
                next->span.begin = value->span.begin;
                next->text = name.text;
                next->values.push_back(std::move(value));
                appendCallArguments(*next);
                value = std::move(next);
            }
            else if (check(TokenKind::LeftParen))
            {
                auto next = std::make_shared<Expr>();
                next->kind = Expr::Kind::Call;
                next->span.begin = value->span.begin;
                next->values.push_back(std::move(value));
                appendCallArguments(*next);
                value = std::move(next);
            }
            else
                break;
        }
        return value;
    }

    void appendCallArguments(Expr& call)
    {
        expect(TokenKind::LeftParen, "Call", "expected '(' before call arguments");
        if (!check(TokenKind::RightParen))
        {
            std::vector<ExprPtr> arguments = expressionList();
            call.values.insert(call.values.end(), arguments.begin(), arguments.end());
        }
        Token close = expect(TokenKind::RightParen, "Call", "expected ')' after call arguments");
        call.span.end = close.span.end;
    }

    ExprPtr primary()
    {
        Token token = current();
        ++cursor;
        auto result = std::make_shared<Expr>();
        result->span = token.span;
        switch (token.kind)
        {
        case TokenKind::Nil:
            result->kind = Expr::Kind::Nil;
            return result;
        case TokenKind::True:
        case TokenKind::False:
            result->kind = Expr::Kind::Boolean;
            result->boolean = token.kind == TokenKind::True;
            return result;
        case TokenKind::Number:
        {
            result->kind = Expr::Kind::Number;
            std::string cleaned;
            for (char value : token.text)
            {
                if (value != '_')
                    cleaned.push_back(value);
            }
            char* end = nullptr;
            result->number = std::strtod(cleaned.c_str(), &end);
            if (!end || *end != '\0')
                fail("invalid_number", "Number", token.span, "invalid numeric literal");
            return result;
        }
        case TokenKind::String:
            result->kind = Expr::Kind::String;
            result->text = token.text;
            return result;
        case TokenKind::Interpolation:
            return interpolationExpression(token);
        case TokenKind::Identifier:
            result->kind = Expr::Kind::Name;
            result->text = token.text;
            return result;
        case TokenKind::Ellipsis:
            result->kind = Expr::Kind::Varargs;
            return result;
        case TokenKind::LeftParen:
            result->kind = Expr::Kind::Group;
            result->values.push_back(expression());
            result->span.end = expect(TokenKind::RightParen, "Group", "expected ')' after expression").span.end;
            return result;
        case TokenKind::LeftBrace:
            --cursor;
            return tableExpression();
        case TokenKind::Fn:
            return functionExpression(token);
        case TokenKind::If:
            return ifExpression(token);
        default:
            fail("expected_expression", "Expression", token.span, "expected an Alex expression");
        }
    }

    ExprPtr tableExpression()
    {
        Token begin = expect(TokenKind::LeftBrace, "Table", "expected '{'");
        auto result = std::make_shared<Expr>();
        result->kind = Expr::Kind::Table;
        result->span.begin = begin.span.begin;
        consumeTerminators();
        while (!check(TokenKind::RightBrace))
        {
            TableItem item;
            item.span.begin = current().span.begin;
            if (match(TokenKind::LeftBracket))
            {
                item.kind = TableItem::Kind::Index;
                item.key = expression();
                expect(TokenKind::RightBracket, "TableItem", "expected ']' after table key");
                expect(TokenKind::Assign, "TableItem", "expected '=' after table key");
                item.value = expression();
            }
            else if (check(TokenKind::Identifier) && cursor + 1 < tokens.size() && tokens[cursor + 1].kind == TokenKind::Assign)
            {
                item.kind = TableItem::Kind::Record;
                item.name = current().text;
                ++cursor;
                ++cursor;
                item.value = expression();
            }
            else
            {
                item.kind = TableItem::Kind::List;
                item.value = expression();
            }
            item.span.end = item.value->span.end;
            result->tableItems.push_back(std::move(item));
            if (!match(TokenKind::Comma) && !match(TokenKind::Semicolon) && !match(TokenKind::Newline))
                break;
            consumeTerminators();
        }
        result->span.end = expect(TokenKind::RightBrace, "Table", "expected '}' after table constructor").span.end;
        return result;
    }

    ExprPtr ifExpression(const Token& begin)
    {
        auto result = std::make_shared<Expr>();
        result->kind = Expr::Kind::IfElse;
        result->span.begin = begin.span.begin;
        result->values.push_back(expression());
        consumeTerminators();
        result->body = block();
        consumeTerminators();
        expect(TokenKind::Else, "IfExpression", "expected 'else' in if expression");
        consumeTerminators();
        result->elseBody = block();
        result->span.end = result->elseBody->span.end;
        return result;
    }

    ExprPtr interpolationExpression(const Token& token)
    {
        auto result = std::make_shared<Expr>();
        result->kind = Expr::Kind::Interpolation;
        result->span = token.span;
        size_t start = 0;
        for (size_t index = 0; index < token.text.size(); ++index)
        {
            if (token.text[index] != '{')
                continue;
            if (index > start)
            {
                auto literal = std::make_shared<Expr>();
                literal->kind = Expr::Kind::String;
                literal->span = token.span;
                literal->text = token.text.substr(start, index - start);
                result->values.push_back(std::move(literal));
            }
            size_t depth = 1;
            size_t close = index + 1;
            for (; close < token.text.size() && depth != 0; ++close)
            {
                if (token.text[close] == '{')
                    ++depth;
                else if (token.text[close] == '}')
                    --depth;
            }
            if (depth != 0)
                fail("unterminated_interpolation_expression", "Interpolation", token.span, "missing '}' in interpolated string");
            std::string_view nested(token.text.data() + index + 1, close - index - 2);
            Lexer nestedLexer(nested);
            Parser nestedParser(nestedLexer.scan());
            Program nestedProgram = nestedParser.parseProgram();
            if (nestedProgram.root->statements.size() != 1 || nestedProgram.root->statements.front()->kind != Statement::Kind::Expression)
                fail("invalid_interpolation_expression", "Interpolation", token.span, "interpolation braces must contain one expression");
            result->values.push_back(nestedProgram.root->statements.front()->values.front());
            index = close - 1;
            start = close;
        }
        if (start < token.text.size() || result->values.empty())
        {
            auto literal = std::make_shared<Expr>();
            literal->kind = Expr::Kind::String;
            literal->span = token.span;
            literal->text = token.text.substr(start);
            result->values.push_back(std::move(literal));
        }
        return result;
    }

    static int binaryPrecedence(TokenKind kind)
    {
        switch (kind)
        {
        case TokenKind::Or:
            return 1;
        case TokenKind::And:
            return 2;
        case TokenKind::Equal:
        case TokenKind::NotEqual:
        case TokenKind::Less:
        case TokenKind::LessEqual:
        case TokenKind::Greater:
        case TokenKind::GreaterEqual:
            return 3;
        case TokenKind::Concat:
            return 4;
        case TokenKind::Add:
        case TokenKind::Subtract:
            return 5;
        case TokenKind::Multiply:
        case TokenKind::Divide:
        case TokenKind::FloorDiv:
        case TokenKind::Modulo:
            return 6;
        case TokenKind::Power:
            return 8;
        default:
            return 0;
        }
    }

    static bool isRightAssociative(TokenKind kind)
    {
        return kind == TokenKind::Power || kind == TokenKind::Concat;
    }

    static std::string operationText(TokenKind kind)
    {
        switch (kind)
        {
        case TokenKind::Or:
            return "or";
        case TokenKind::And:
            return "and";
        case TokenKind::Not:
            return "not";
        case TokenKind::Equal:
            return "==";
        case TokenKind::NotEqual:
            return "~=";
        case TokenKind::Less:
            return "<";
        case TokenKind::LessEqual:
            return "<=";
        case TokenKind::Greater:
            return ">";
        case TokenKind::GreaterEqual:
            return ">=";
        case TokenKind::Concat:
            return "..";
        case TokenKind::Add:
            return "+";
        case TokenKind::Subtract:
            return "-";
        case TokenKind::Multiply:
            return "*";
        case TokenKind::Divide:
            return "/";
        case TokenKind::FloorDiv:
            return "//";
        case TokenKind::Modulo:
            return "%";
        case TokenKind::Power:
            return "^";
        case TokenKind::Hash:
            return "#";
        default:
            return {};
        }
    }
};

class Binder
{
public:
    std::vector<Diagnostic> run(const Program& program)
    {
        scopes.emplace_back();
        visitBlock(program.root, false);
        scopes.pop_back();
        return std::move(diagnostics);
    }

private:
    std::vector<std::unordered_set<std::string>> scopes;
    std::vector<Diagnostic> diagnostics;
    int loopDepth = 0;
    std::vector<bool> variadicFunctions{true};

    void report(std::string code, std::string kind, Span span, std::string message)
    {
        diagnostics.push_back({"bind", std::move(code), std::move(kind), std::move(message), span});
    }

    void declareName(const std::string& name, Span span)
    {
        if (!scopes.back().insert(name).second)
            report("duplicate_local", "Local", span, "a local with this name is already declared in the current scope");
    }

    void visitBlock(const BlockPtr& block, bool nested)
    {
        if (nested)
            scopes.emplace_back();
        for (const StatementPtr& statement : block->statements)
            visitStatement(statement);
        if (nested)
            scopes.pop_back();
    }

    void visitFunction(const ExprPtr& expression)
    {
        scopes.emplace_back();
        variadicFunctions.push_back(expression->variadic);
        for (const std::string& parameter : expression->names)
            declareName(parameter, expression->span);
        visitBlock(expression->body, false);
        variadicFunctions.pop_back();
        scopes.pop_back();
    }

    void visitExpression(const ExprPtr& expression)
    {
        if (!expression)
            return;
        if (expression->kind == Expr::Kind::Varargs && !variadicFunctions.back())
            report("varargs_outside_variadic_function", "Varargs", expression->span, "varargs are only available inside a variadic function");
        if (expression->kind == Expr::Kind::Function)
            visitFunction(expression);
        else
        {
            for (const ExprPtr& value : expression->values)
                visitExpression(value);
            for (const TableItem& item : expression->tableItems)
            {
                visitExpression(item.key);
                visitExpression(item.value);
            }
            if (expression->body)
                visitBlock(expression->body, true);
            if (expression->elseBody)
                visitBlock(expression->elseBody, true);
        }
    }

    static bool validTarget(const ExprPtr& expression)
    {
        return expression && (expression->kind == Expr::Kind::Name || expression->kind == Expr::Kind::Index || expression->kind == Expr::Kind::IndexName);
    }

    void visitStatement(const StatementPtr& statement)
    {
        if (statement->kind == Statement::Kind::Break || statement->kind == Statement::Kind::Continue)
        {
            if (loopDepth == 0)
                report("loop_control_outside_loop", statementKindName(statement->kind), statement->span, "loop control is only valid inside a loop");
            return;
        }
        if (statement->kind == Statement::Kind::Let)
        {
            for (const ExprPtr& value : statement->values)
                visitExpression(value);
            for (const std::string& name : statement->names)
                declareName(name, statement->span);
            return;
        }
        if (statement->kind == Statement::Kind::Function)
        {
            declareName(statement->names.front(), statement->span);
            visitExpression(statement->values.front());
            return;
        }
        if (statement->kind == Statement::Kind::Assign || statement->kind == Statement::Kind::CompoundAssign)
        {
            for (const ExprPtr& target : statement->targets)
            {
                if (!validTarget(target))
                    report("invalid_assignment_target", expressionKindName(target->kind), target->span, "this expression cannot be assigned to");
                visitExpression(target);
            }
        }
        for (const ExprPtr& value : statement->values)
            visitExpression(value);
        visitExpression(statement->condition);

        if (statement->kind == Statement::Kind::ForNumeric || statement->kind == Statement::Kind::ForIn)
        {
            ++loopDepth;
            scopes.emplace_back();
            for (const std::string& name : statement->names)
                declareName(name, statement->span);
            visitBlock(statement->body, false);
            scopes.pop_back();
            --loopDepth;
        }
        else if (statement->kind == Statement::Kind::While || statement->kind == Statement::Kind::Repeat)
        {
            ++loopDepth;
            visitBlock(statement->body, true);
            --loopDepth;
        }
        else if (statement->body)
            visitBlock(statement->body, true);
        if (statement->elseBody)
            visitBlock(statement->elseBody, true);
    }
};

} // namespace

ParseResult parse(std::string_view source)
{
    ParseResult result;
    try
    {
        Lexer lexer(source);
        Parser parser(lexer.scan());
        result.program = parser.parseProgram();
    }
    catch (const FrontendError& error)
    {
        result.diagnostics.push_back(error.diagnostic);
    }
    return result;
}

std::vector<Diagnostic> bind(const Program& program)
{
    if (!program.root)
        return {{"bind", "missing_program", "Program", {}, {}}};
    return Binder().run(program);
}

std::string expressionKindName(Expr::Kind kind)
{
    static const char* names[] = {"Nil", "Boolean", "Number", "String", "Interpolation", "Name", "Varargs", "Group", "Unary", "Binary", "Index",
        "IndexName", "Call", "MethodCall", "Function", "Table", "IfElse"};
    return names[static_cast<size_t>(kind)];
}

std::string statementKindName(Statement::Kind kind)
{
    static const char* names[] = {"Let", "Function", "Return", "Expression", "Assign", "CompoundAssign", "If", "While", "Repeat", "ForNumeric", "ForIn",
        "Break", "Continue", "Scope"};
    return names[static_cast<size_t>(kind)];
}

} // namespace alex::lang
