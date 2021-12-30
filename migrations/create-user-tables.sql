CREATE TABLE IF NOT EXISTS Users
(
    id       INTEGER NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password TEXT,
    PRIMARY KEY(id)
);

CREATE TABLE IF NOT EXISTS Emails 
(
    user_id     INTEGER NOT NULL,
    address     TEXT NOT NULL UNIQUE, 
    is_verified BOOL NOT NULL,
    FOREIGN KEY(user_id) REFERENCES Users(id)
);

CREATE TABLE IF NOT EXISTS EthereumAddresses
(
    user_id     INTEGER NOT NULL,
    address     TEXT NOT NULL UNIQUE, 
    is_verified BOOL NOT NULL,
    FOREIGN KEY(user_id) REFERENCES Users(id)
);

CREATE TABLE IF NOT EXISTS LoginTokens
(
    user_id     INTEGER NOT NULL,
    token       TEXT NOT NULL UNIQUE, 
    FOREIGN KEY(user_id) REFERENCES Users(id)
);

-- If MySQL
-- ALTER TABLE Users MODIFY COLUMN id BIGINT AUTO_INCREMENT;
-- Note that the foreign key types of referencing tables also need to be updated