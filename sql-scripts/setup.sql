
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name  TEXT NOT NULL CHECK (LENGTH(user_name) <= 24),
    password TEXT NOT NULL,
    salt TEXT
);

CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT ,
    url TEXT,
    username TEXT NOT NULL,
    password_enc TEXT NOT NULL
);

truncate table entries;