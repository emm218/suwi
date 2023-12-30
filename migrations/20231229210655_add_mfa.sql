ALTER TABLE accounts 
ADD COLUMN mfa_secret bytea,
ADD COLUMN mfa_enabled boolean NOT NULL DEFAULT false;

CREATE TABLE mfa_tokens(
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES accounts(id),
    valid_until timestamptz NOT NULL,
    PRIMARY KEY(id)
);

CREATE INDEX ON mfa_tokens(valid_until);
