CREATE TABLE accounts(
    id uuid NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    registered_at timestamptz NOT NULL,
    PRIMARY KEY(id)
);
