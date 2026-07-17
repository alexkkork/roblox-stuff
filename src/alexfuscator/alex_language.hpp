#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace alex::lang
{

struct Position
{
    int line = 1;
    int column = 1;
    size_t offset = 0;
};

struct Span
{
    Position begin;
    Position end;
};

struct Diagnostic
{
    std::string stage;
    std::string code;
    std::string kind;
    std::string message;
    Span span;
};

struct Expr;
struct Statement;
struct Block;

using ExprPtr = std::shared_ptr<Expr>;
using StatementPtr = std::shared_ptr<Statement>;
using BlockPtr = std::shared_ptr<Block>;

struct TableItem
{
    enum class Kind
    {
        List,
        Record,
        Index,
    };

    Kind kind = Kind::List;
    std::string name;
    ExprPtr key;
    ExprPtr value;
    Span span;
};

struct Expr
{
    enum class Kind
    {
        Nil,
        Boolean,
        Number,
        String,
        Interpolation,
        Name,
        Varargs,
        Group,
        Unary,
        Binary,
        Index,
        IndexName,
        Call,
        MethodCall,
        Function,
        Table,
        IfElse,
    };

    Kind kind = Kind::Nil;
    Span span;
    std::string text;
    double number = 0.0;
    bool boolean = false;
    bool variadic = false;
    std::vector<std::string> names;
    std::vector<ExprPtr> values;
    std::vector<TableItem> tableItems;
    BlockPtr body;
    BlockPtr elseBody;
};

struct Statement
{
    enum class Kind
    {
        Let,
        Function,
        Return,
        Expression,
        Assign,
        CompoundAssign,
        If,
        While,
        Repeat,
        ForNumeric,
        ForIn,
        Break,
        Continue,
        Scope,
    };

    Kind kind = Kind::Expression;
    Span span;
    std::string text;
    std::vector<std::string> names;
    std::vector<ExprPtr> targets;
    std::vector<ExprPtr> values;
    ExprPtr condition;
    BlockPtr body;
    BlockPtr elseBody;
};

struct Block
{
    Span span;
    std::vector<StatementPtr> statements;
};

struct Program
{
    BlockPtr root;
};

struct ParseResult
{
    Program program;
    std::vector<Diagnostic> diagnostics;

    explicit operator bool() const
    {
        return program.root != nullptr && diagnostics.empty();
    }
};

ParseResult parse(std::string_view source);
std::vector<Diagnostic> bind(const Program& program);
std::string expressionKindName(Expr::Kind kind);
std::string statementKindName(Statement::Kind kind);

} // namespace alex::lang
