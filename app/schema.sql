DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS message;
DROP TABLE IF EXISTS forgot_link;
DROP TABLE IF EXISTS activation_link;
DROP TABLE IF EXISTS credentials;

CREATE TABLE user
(
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT        NOT NULL,
    email    TEXT        NOT NULL,
    state    TEXT        NOT NULL DEFAULT 'UNCONFIRMED'
);

CREATE TABLE forgot_link
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    id_user     INTEGER   NOT NULL,
    validator   TEXT      NOT NULL,
    created     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMP NOT NULL DEFAULT (DATETIME(CURRENT_TIMESTAMP, '+1 days')),
    state       TEXT      NOT NULL DEFAULT 'ACTIVE',
    FOREIGN KEY (id_user) REFERENCES user (id)
);

CREATE TABLE activation_link
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    id_user     INTEGER   NOT NULL,
    validator   TEXT      NOT NULL,
    created     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMP NOT NULL DEFAULT (DATETIME(CURRENT_TIMESTAMP, '+1 days')),
    state       TEXT      NOT NULL,
    FOREIGN KEY (id_user) REFERENCES user (id)
);

CREATE TABLE message
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    creator      TEXT      NOT NULL,
    id_user_from INTEGER   NOT NULL,
    id_user_to   INTEGER   NOT NULL,
    created      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    subject      TEXT      NOT NULL,
    body         TEXT      NOT NULL,
    FOREIGN KEY (id_user_from) REFERENCES user (id),
    FOREIGN KEY (id_user_to) REFERENCES user (id)
);

CREATE TABLE credentials
(
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL,
    user     TEXT NOT NULL,
    password TEXT NOT NULL
);

INSERT INTO credentials (name, user, password)
VALUES ('EMAIL_APP', 'smtp@gmail.com', 'PASSWORD');