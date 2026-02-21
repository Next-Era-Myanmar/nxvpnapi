CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    display_name TEXT,
    username TEXT NOT NULL UNIQUE,
    password_hashed TEXT NOT NULL,
    contact_email TEXT,
    expired_at TIMESTAMP,
    refresh_token TEXT,
    "type" VARCHAR(10) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE outline_keys (
    id SERIAL PRIMARY KEY,
    name TEXT,
    outline_key TEXT,
    country TEXT,
    parent_id INTEGER REFERENCES outline_keys(id) ON DELETE SET NULL
);

CREATE TABLE user_access_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    outline_key_id INTEGER NOT NULL REFERENCES outline_keys(id) ON DELETE CASCADE
);
