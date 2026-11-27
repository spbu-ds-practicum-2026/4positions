"""Synchronous PostgreSQL repository. FastAPI runs sync routes in a thread pool."""


class DatabaseUnavailable(Exception):
    pass


class PostgresUsers:
    def __init__(self, dsn: str):
        self.dsn = dsn

    def _query(self, sql, params=(), fetch=True):
        import psycopg
        try:
            with psycopg.connect(self.dsn, connect_timeout=3,
                                 options='-c statement_timeout=5000 -c lock_timeout=4000') as conn:
                cursor = conn.execute(sql, params)
                result = cursor.fetchone() if fetch else None
            # Return only after successful commit on context exit.
            return result
        except psycopg.Error as exc:
            raise DatabaseUnavailable() from exc

    def initialize(self):
        self._query('''
            CREATE TABLE IF NOT EXISTS users (
                user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                login VARCHAR(64) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT login_format CHECK (login ~ '^[A-Za-z0-9_.-]{3,64}$')
            );
        ''', fetch=False)

    def create(self, login: str, password_hash: str):
        row = self._query('''INSERT INTO users (login, password_hash) VALUES (%s, %s)
                              ON CONFLICT (login) DO NOTHING RETURNING user_id''',
                          (login, password_hash))
        return row[0] if row else None

    def find(self, login: str):
        return self._query('SELECT user_id, password_hash FROM users WHERE login = %s', (login,))
