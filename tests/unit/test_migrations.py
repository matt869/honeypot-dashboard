"""Tests for the lightweight SQL migration runner.

``_split_statements`` is a deliberately small substitute for Alembic, and its
one subtle job is knowing where a statement ends. The trap it used to fall into
is worth a permanent test: splitting on the semicolon before stripping comments
means a semicolon *inside* a comment ends the chunk early, and the rest of that
comment line survives as SQL. Two migrations in this repo hit it, the second
written by someone who had already documented the trap in the first.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import text

from storage.db import _split_statements, get_engine, init_db, session_scope

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent.parent / "storage" / "migrations"


class TestSplitStatements:
    def test_semicolon_inside_a_comment_does_not_split(self):
        sql = """-- metadata (storage/models.py); this adds the pair we sort on.
CREATE INDEX ix_a ON t (a);"""
        statements = _split_statements(sql)
        assert statements == ["CREATE INDEX ix_a ON t (a)"]

    def test_multiple_statements_are_separated(self):
        sql = "CREATE INDEX ix_a ON t (a);\nCREATE INDEX ix_b ON t (b);"
        assert len(_split_statements(sql)) == 2

    def test_comments_and_blank_lines_are_dropped(self):
        sql = """-- a heading
--

CREATE INDEX ix_a ON t (a);
-- trailing note
"""
        assert _split_statements(sql) == ["CREATE INDEX ix_a ON t (a)"]

    def test_a_file_of_only_comments_yields_nothing(self):
        assert _split_statements("-- nothing here;\n-- really; nothing\n") == []

    def test_trailing_semicolon_does_not_produce_an_empty_statement(self):
        assert _split_statements("CREATE INDEX ix_a ON t (a);\n") == ["CREATE INDEX ix_a ON t (a)"]

    def test_statement_without_a_trailing_semicolon_still_parses(self):
        assert _split_statements("CREATE INDEX ix_a ON t (a)") == ["CREATE INDEX ix_a ON t (a)"]


class TestShippedMigrations:
    def test_every_migration_parses_to_real_statements(self):
        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            statements = _split_statements(path.read_text(encoding="utf-8"))
            assert statements, f"{path.name} produced no statements"
            for statement in statements:
                assert statement.upper().startswith(
                    ("CREATE", "ALTER", "DROP", "INSERT", "UPDATE")
                ), f"{path.name}: {statement[:60]!r} does not look like SQL"

    def test_all_migrations_apply_to_a_fresh_database(self, engine):
        with session_scope() as db:
            applied = {r[0] for r in db.execute(text("SELECT filename FROM schema_migrations"))}
        assert applied == {p.name for p in MIGRATIONS_DIR.glob("*.sql")}

    def test_reapplying_is_a_no_op(self, db_url, monkeypatch):
        # The runner records what it has applied, so a second init must not
        # re-run anything or fail on an existing index.
        monkeypatch.setenv("DATABASE_URL", db_url)
        init_db(get_engine(db_url))
        init_db(get_engine(db_url))
        with session_scope() as db:
            count = db.execute(text("SELECT count(*) FROM schema_migrations")).scalar_one()
        assert count == len(list(MIGRATIONS_DIR.glob("*.sql")))
