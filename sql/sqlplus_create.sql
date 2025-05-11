CREATE TABLE User (
    user_id TEXT PRIMARY KEY,
    user_pw TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_phone TEXT NOT NULL,
    user_email TEXT NOT NULL,
    policy_id INTEGER,
    FOREIGN KEY(policy_id) REFERENCES Policy(policy_id)
); 

CREATE TABLE URL (
    url_id INTEGER PRIMARY KEY,
    url_pattern TEXT NOT NULL
);

CREATE TABLE Policy (
    policy_id INTEGER PRIMARY KEY,
    policy_name TEXT
);

CREATE TABLE Policy_URL (
    policy_url_id INTEGER PRIMARY KEY,
    policy_id INTEGER NOT NULL,
    url_id INTEGER NOT NULL,
    FOREIGN KEY (policy_id) REFERENCES Policy(policy_id),
    FOREIGN KEY (url_id) REFERENCES URL(url_id)
);
