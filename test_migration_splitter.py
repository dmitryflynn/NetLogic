"""
Regression: the migration SQL splitter must be comment- and string-aware.

A header comment in 0001 contains a semicolon ("owned by the IdP; we only verify
its tokens and …"). The old naive `text.split(';')` turned the comment tail into
a bogus statement, so EVERY real `apply_migrations()` failed with a syntax error
— a bug invisible to offline tests because they never executed the SQL. Pin the
behavior here.
"""
from pathlib import Path

from api.db import _split_sql


def test_semicolon_inside_line_comment_does_not_split():
    assert _split_sql("-- note; still a comment\nCREATE TABLE t (id int);") == [
        "CREATE TABLE t (id int)"
    ]


def test_semicolon_inside_string_literal_does_not_split():
    assert _split_sql("INSERT INTO t VALUES ('a;b'); SELECT 1;") == [
        "INSERT INTO t VALUES ('a;b')",
        "SELECT 1",
    ]


def test_begin_commit_dropped():
    assert _split_sql("BEGIN; CREATE TABLE t (id int); COMMIT;") == ["CREATE TABLE t (id int)"]


def test_real_migrations_produce_only_valid_statements():
    # Every statement parsed from a real migration must start with a DDL/DML
    # keyword — never a fragment of prose from a comment.
    starts = ("CREATE", "INSERT", "ALTER", "DROP", "UPDATE", "DELETE", "WITH", "GRANT", "COMMENT")
    for f in sorted(Path("db/migrations").glob("*.sql")):
        stmts = _split_sql(f.read_text(encoding="utf-8"))
        assert stmts, f"{f.name} produced no statements"
        for stmt in stmts:
            assert stmt.upper().startswith(starts), f"{f.name}: bogus statement {stmt[:60]!r}"
