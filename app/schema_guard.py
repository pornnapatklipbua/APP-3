"""A lightweight stand-in for a migration tool.

``db.create_all()`` only creates tables that do not exist yet -- it never
alters one that is already there. Every column added to a model after the
first production deploy has to reach the live database some other way, or
every query touching it fails with "column does not exist". This project has
no Alembic/Flask-Migrate, so this runs on every boot instead: it compares each
model's columns against what the live table actually has, and adds whatever is
missing.

Deliberately narrow. It only ever issues ``ADD COLUMN`` for a column that does
not exist -- never drops, renames, or alters a type -- so a boot that finds
nothing to do is a silent no-op, and there is no path here that can touch a
row of existing data.
"""

from __future__ import annotations

import sqlalchemy as sa


def ensure_columns(app, db) -> None:
    inspector = sa.inspect(db.engine)

    with db.engine.begin() as conn:
        for table in db.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue  # create_all() will have made this one correctly.

            existing = {c["name"] for c in inspector.get_columns(table.name)}

            for column in table.columns:
                if column.name in existing:
                    continue

                ddl = _add_column_ddl(table, column, conn.dialect)
                if ddl is None:
                    app.logger.error(
                        "Column %s.%s is missing in the database and has no "
                        "plain default, so it cannot be added automatically. "
                        "Add it by hand.",
                        table.name,
                        column.name,
                    )
                    continue

                app.logger.warning(
                    "Adding missing column %s.%s (schema_guard)",
                    table.name,
                    column.name,
                )
                conn.execute(sa.text(ddl))


def _add_column_ddl(table: sa.Table, column: sa.Column, dialect) -> str | None:
    type_sql = column.type.compile(dialect=dialect)
    parts = [f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {type_sql}']

    if not column.nullable:
        default_sql = _literal_default(column)
        if default_sql is None:
            # A NOT NULL column with no expressible default cannot be added to
            # a table that may already have rows -- the ALTER would fail on
            # the backfill regardless. Leave it for a human.
            return None
        parts.append(f"NOT NULL DEFAULT {default_sql}")

    return " ".join(parts)


def _literal_default(column: sa.Column) -> str | None:
    """Render a column's Python-side default as a SQL literal, if possible.

    Only handles a plain scalar default (``default=3``, ``default="scan"``,
    ``default=True``) -- exactly what every column in this project's models
    uses. A callable default (like the ``_utcnow`` timestamps) has no single
    value that could backfill existing rows, so those are intentionally left
    for a human rather than guessed at.
    """
    if column.default is None or not column.default.is_scalar:
        return None

    value = column.default.arg
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    return None
