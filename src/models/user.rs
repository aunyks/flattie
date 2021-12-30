use log::{debug, error, trace, warn};
use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt,
};
use sqlx::{AnyPool, Row};

#[derive(PartialEq, Eq, Debug)]
pub struct User {
    username: String,
    password: Option<String>,
}

impl User {
    pub async fn create(
        username: String,
        plaintext_password: Option<String>,
        conn_pool: &AnyPool,
    ) -> Result<User, &str> {
        trace!("User::create(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        match plaintext_password {
            Some(plaintext_pass) => {
                let salt = SaltString::generate(&mut OsRng);
                // Password string format:
                // https://github.com/P-H-C/phc-string-format/blob/5f1e4ec633845d43776849f503f8ce8314b5290c/phc-sf-spec.md
                let hashed_password = match Scrypt.hash_password(plaintext_pass.as_bytes(), &salt) {
                    Ok(hashed_pass) => hashed_pass.to_string(),
                    Err(err) => {
                        error!("Could not hash password! {}", err.to_string());
                        return Err("Could not hash password!");
                    }
                };
                match sqlx::query("INSERT INTO Users (username, password) VALUES (?, ?)")
                    .bind(&username)
                    .bind(&hashed_password)
                    .execute(&mut sql_connection)
                    .await
                {
                    Ok(raw_row) => raw_row,
                    Err(err) => {
                        error!("User creation SQL query failed! {}", err.to_string());
                        return Err("User creation SQL query failed!");
                    }
                };

                Ok(User {
                    username: username,
                    password: Some(hashed_password),
                })
            }
            None => {
                match sqlx::query("INSERT INTO Users (username) VALUES (?)")
                    .bind(&username)
                    .execute(&mut sql_connection)
                    .await
                {
                    Ok(raw_row) => raw_row,
                    Err(err) => {
                        error!("User creation SQL query failed! {}", err.to_string());
                        return Err("User could not create new user!");
                    }
                };

                Ok(User {
                    username: username,
                    password: None,
                })
            }
        }
    }

    pub async fn with_username(username: String, conn_pool: &AnyPool) -> Result<User, &str> {
        trace!("User::with_username(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        let row = match sqlx::query("SELECT * FROM Users WHERE username = ?")
            .bind(&username)
            .fetch_one(&mut sql_connection)
            .await
        {
            Ok(raw_row) => raw_row,
            Err(err) => {
                error!("Could not fetch user by username! {}", err.to_string());
                return Err("Could not fetch user by username!");
            }
        };
        let username = row.get::<String, _>("username");
        let password = row.get::<Option<String>, _>("password");
        Ok(User {
            username: username,
            password: password,
        })
    }

    pub fn has_password(&self, possible_password: String) -> bool {
        trace!("User.has_password(): Invoked");
        let this_password = match self.password.clone() {
            Some(pass) => pass,
            None => {
                debug!("User.has_password(): User does not have a password");
                return false;
            }
        };
        let hashed_password = match PasswordHash::new(this_password.as_str()) {
            Ok(hashed_pass) => hashed_pass,
            Err(err) => {
                error!(
                    "User.has_password(): Could not hash provided password, {}",
                    err.to_string()
                );
                return false;
            }
        };
        Scrypt
            .verify_password(possible_password.as_bytes(), &hashed_password)
            .is_ok()
    }

    pub async fn add_email(
        &self,
        email: String,
        is_verified: bool,
        conn_pool: &AnyPool,
    ) -> Result<(), &str> {
        trace!("User.add_email(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        match sqlx::query("INSERT INTO Emails (user_id, address, is_verified) VALUES ((SELECT id FROM Users WHERE username = ?), ?, ?)")
                    .bind(&self.username)
                    .bind(&email)
                    .bind(&is_verified)
                    .execute(&mut sql_connection)
                    .await
                {
                    Ok(raw_row) => raw_row,
                    Err(err) => {
                        error!("Email addition SQL query failed! {}", err.to_string());
                        return Err("Email addition SQL query failed!");
                    }
                };
        Ok(())
    }

    pub async fn with_email(email: String, conn_pool: &AnyPool) -> Result<User, &str> {
        trace!("User::with_email(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        let row = match sqlx::query(
            "SELECT * FROM Users WHERE id = (SELECT user_id FROM Emails WHERE address = ?)",
        )
        .bind(&email)
        .fetch_one(&mut sql_connection)
        .await
        {
            Ok(raw_row) => raw_row,
            Err(err) => {
                error!("Could not fetch user by email! {}", err.to_string());
                return Err("Could not fetch user by email!");
            }
        };
        let username = row.get::<String, _>("username");
        let password = row.get::<Option<String>, _>("password");
        Ok(User {
            username: username,
            password: password,
        })
    }

    pub async fn delete_email(&self, email: String, conn_pool: &AnyPool) -> Result<(), &str> {
        trace!("User.delete_email(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        match sqlx::query("DELETE FROM Emails WHERE address = ?")
            .bind(&email)
            .execute(&mut sql_connection)
            .await
        {
            Ok(raw_row) => raw_row,
            Err(err) => {
                error!("Email deletion SQL query failed! {}", err.to_string());
                return Err("Email deletion SQL query failed!");
            }
        };
        Ok(())
    }

    pub async fn update_email(&self, email: String, conn_pool: &AnyPool) -> Result<(), &str> {
        trace!("User.update_email(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        match sqlx::query(
            "UPDATE Emails SET address = ? WHERE (SELECT id FROM Users WHERE username = ?)",
        )
        .bind(&email)
        .bind(&self.username)
        .execute(&mut sql_connection)
        .await
        {
            Ok(raw_row) => raw_row,
            Err(err) => {
                error!("Email update SQL query failed! {}", err.to_string());
                return Err("Email update SQL query failed!");
            }
        };
        Ok(())
    }

    pub async fn update_email_verification_status(
        &self,
        is_verified: bool,
        conn_pool: &AnyPool,
    ) -> Result<(), &str> {
        trace!("User.update_email_verification_status(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        match sqlx::query(
            "UPDATE Emails SET is_verified = ? WHERE (SELECT id FROM Users WHERE username = ?)",
        )
        .bind(&is_verified)
        .bind(&self.username)
        .execute(&mut sql_connection)
        .await
        {
            Ok(raw_row) => raw_row,
            Err(err) => {
                error!(
                    "Email verification status update SQL query failed! {}",
                    err.to_string()
                );
                return Err("Email verification status update SQL query failed!");
            }
        };
        Ok(())
    }

    pub async fn has_verified_email(&self, email: String, conn_pool: &AnyPool) -> bool {
        trace!("User.has_verified_email(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return false;
            }
        };
        let row = match sqlx::query(
            "SELECT is_verified FROM Emails WHERE address = ? AND user_id = (SELECT id FROM Users WHERE username = ?)",
        )
        .bind(&email)
        .bind(&self.username)
        .fetch_one(&mut sql_connection)
        .await
        {
            Ok(raw_row) => raw_row,
            Err(err) => {
                error!("Could not fetch user by email! {}", err.to_string());
                return false;
            }
        };
        let is_verified = row.get::<Option<bool>, _>("is_verified");
        match is_verified {
            Some(verified) => verified,
            None => {
                warn!("is_verified column was NULL for user");
                false
            }
        }
    }

    pub async fn add_eth_address(
        &self,
        eth_address: String,
        is_verified: bool,
        conn_pool: &AnyPool,
    ) -> Result<(), &str> {
        trace!("User.add_eth_address(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        match sqlx::query("INSERT INTO EthereumAddresses (user_id, address, is_verified) VALUES ((SELECT id FROM Users WHERE username = ?), ?, ?)")
                    .bind(&self.username)
                    .bind(&eth_address)
                    .bind(&is_verified)
                    .execute(&mut sql_connection)
                    .await
                {
                    Ok(raw_row) => raw_row,
                    Err(err) => {
                        error!("Ethereum address addition SQL query failed! {}", err.to_string());
                        return Err("Ethereum address addition SQL query failed!");
                    }
                };
        Ok(())
    }

    pub async fn with_eth_address(eth_address: String, conn_pool: &AnyPool) -> Result<User, &str> {
        trace!("User::with_eth_address(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        let row = match sqlx::query(
            "SELECT * FROM Users WHERE id = (SELECT user_id FROM EthereumAddresses WHERE address = ?)",
        )
        .bind(&eth_address)
        .fetch_one(&mut sql_connection)
        .await
        {
            Ok(raw_row) => raw_row,
            Err(err) => {
                error!("Could not fetch user by Ethereum address! {}", err.to_string());
                return Err("Could not fetch user by Ethereum address!");
            }
        };
        let username = row.get::<String, _>("username");
        let password = row.get::<Option<String>, _>("password");
        Ok(User {
            username: username,
            password: password,
        })
    }

    pub async fn delete_eth_address(
        &self,
        eth_address: String,
        conn_pool: &AnyPool,
    ) -> Result<(), &str> {
        trace!("User.delete_eth_address(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        match sqlx::query("DELETE FROM EthereumAddresses WHERE address = ?")
            .bind(&eth_address)
            .execute(&mut sql_connection)
            .await
        {
            Ok(raw_row) => raw_row,
            Err(err) => {
                error!(
                    "Ethereum address deletion SQL query failed! {}",
                    err.to_string()
                );
                return Err("Ethereum address deletion SQL query failed!");
            }
        };
        Ok(())
    }

    pub async fn update_eth_address(
        &self,
        eth_address: String,
        conn_pool: &AnyPool,
    ) -> Result<(), &str> {
        trace!("User.update_eth_address(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        match sqlx::query(
            "UPDATE EthereumAddresses SET address = ? WHERE (SELECT id FROM Users WHERE username = ?)",
        )
        .bind(&eth_address)
        .bind(&self.username)
        .execute(&mut sql_connection)
        .await
        {
            Ok(raw_row) => raw_row,
            Err(err) => {
                error!("Ethereum address update SQL query failed! {}", err.to_string());
                return Err("Ethereum address update SQL query failed!");
            }
        };
        Ok(())
    }

    pub async fn update_eth_addr_verification_status(
        &self,
        is_verified: bool,
        conn_pool: &AnyPool,
    ) -> Result<(), &str> {
        trace!("User.update_eth_addr_verification_status(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        match sqlx::query(
            "UPDATE EthereumAddresses SET is_verified = ? WHERE (SELECT id FROM Users WHERE username = ?)",
        )
        .bind(&is_verified)
        .bind(&self.username)
        .execute(&mut sql_connection)
        .await
        {
            Ok(raw_row) => raw_row,
            Err(err) => {
                error!("Ethereum address verification status update SQL query failed! {}", err.to_string());
                return Err("Ethereum address verification status update SQL query failed!");
            }
        };
        Ok(())
    }

    pub async fn has_verified_eth_address(&self, eth_address: String, conn_pool: &AnyPool) -> bool {
        trace!("User.has_verified_eth_address(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return false;
            }
        };
        let row = match sqlx::query(
            "SELECT is_verified FROM EthereumAddresses WHERE address = ? AND user_id = (SELECT id FROM Users WHERE username = ?)",
        )
        .bind(&eth_address)
        .bind(&self.username)
        .fetch_one(&mut sql_connection)
        .await
        {
            Ok(raw_row) => raw_row,
            Err(err) => {
                error!("Could not fetch user by Ethereum address! {}", err.to_string());
                return false;
            }
        };
        let is_verified = row.get::<Option<bool>, _>("is_verified");
        match is_verified {
            Some(verified) => verified,
            None => {
                warn!("is_verified column was NULL for user");
                false
            }
        }
    }

    pub async fn with_login_token(login_token: String, conn_pool: &AnyPool) -> Result<User, &str> {
        trace!("User::with_login_token(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        let row = match sqlx::query(
            "SELECT * FROM Users WHERE id = (SELECT user_id FROM LoginTokens WHERE token = ?)",
        )
        .bind(&login_token)
        .fetch_one(&mut sql_connection)
        .await
        {
            Ok(raw_row) => raw_row,
            Err(err) => {
                error!("Could not fetch user by login token! {}", err.to_string());
                return Err("Could not fetch user by login token!");
            }
        };
        let username = row.get::<String, _>("username");
        let password = row.get::<Option<String>, _>("password");
        Ok(User {
            username: username,
            password: password,
        })
    }

    pub async fn add_login_token(
        &self,
        login_token: String,
        conn_pool: &AnyPool,
    ) -> Result<(), &str> {
        trace!("User.add_login_token(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        match sqlx::query("INSERT INTO LoginTokens (user_id, token) VALUES ((SELECT id FROM Users WHERE username = ?), ?)")
                    .bind(&self.username)
                    .bind(&login_token)
                    .execute(&mut sql_connection)
                    .await
                {
                    Ok(raw_row) => raw_row,
                    Err(err) => {
                        error!("Login token addition SQL query failed! {}", err.to_string());
                        return Err("Login token addition SQL query failed!");
                    }
                };
        Ok(())
    }

    pub async fn delete_login_token(
        &self,
        login_token: String,
        conn_pool: &AnyPool,
    ) -> Result<(), &str> {
        trace!("User.delete_login_token(): Invoked");
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(
                    "Could not acquire SQL connection from pool! {}",
                    err.to_string()
                );
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        match sqlx::query("DELETE FROM LoginTokens WHERE token = ?")
            .bind(&login_token)
            .execute(&mut sql_connection)
            .await
        {
            Ok(raw_row) => raw_row,
            Err(err) => {
                error!("Login token deletion SQL query failed! {}", err.to_string());
                return Err("Login token deletion SQL query failed!");
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::any::AnyPoolOptions;
    use sqlx::pool::PoolConnection;
    use sqlx::AnyPool;
    use sqlx::Row;

    async fn create_test_sql_pool() -> AnyPool {
        match AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
        {
            Ok(pool) => pool,
            Err(_) => {
                panic!("Could not create start in-memory SQL database!");
            }
        }
    }

    async fn create_user_tables(conn_pool: &AnyPool) {
        let mut connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(_) => {
                panic!("Could not individual connection to SQL database!");
            }
        };
        let command_str = include_str!("../../migrations/create-user-tables.sql");
        match sqlx::query(command_str).execute(&mut connection).await {
            Ok(_) => {}
            Err(err) => {
                panic!(
                    "Could not execute user creation SQL query! {}",
                    err.to_string()
                );
            }
        }
    }

    async fn get_sql_connection(conn_pool: &AnyPool) -> PoolConnection<sqlx::Any> {
        match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(_) => {
                panic!("Could not individual connection to SQL database!");
            }
        }
    }

    #[allow(unused_must_use)]
    #[actix_rt::test]
    async fn user_raw_sql_queries() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;
        // Create a connection for use in this test
        let mut connection = get_sql_connection(&test_pool).await;
        // Insert test data
        sqlx::query("INSERT INTO Users (username, password) VALUES ('my_username', 'password123')")
            .execute(&mut connection)
            .await;
        sqlx::query("INSERT INTO Users (username, password) VALUES ('their_username', 'hunter2')")
            .execute(&mut connection)
            .await;
        let rows = match sqlx::query("SELECT * FROM Users")
            .fetch_all(&mut connection)
            .await
        {
            Ok(raw_row) => raw_row,
            Err(_) => {
                panic!("Couldn't get rows during SELECT");
            }
        };
        let first_row = &rows[0];
        let first_username = first_row.get::<String, _>("username");
        let first_password = first_row.get::<String, _>("password");
        assert_eq!(first_username, String::from("my_username"));
        assert_eq!(first_password, String::from("password123"));
        let second_row = &rows[1];
        let second_username = second_row.get::<String, _>("username");
        let second_password = second_row.get::<String, _>("password");
        assert_eq!(second_username, String::from("their_username"));
        assert_eq!(second_password, String::from("hunter2"));
        let first_id = first_row.get::<i64, _>("id");
        let second_id = second_row.get::<i64, _>("id");
        assert_ne!(second_id, first_id);
    }

    #[actix_rt::test]
    async fn create_no_password() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let new_user = match User::create(String::from("my_username"), None, &test_pool).await {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // Make sure the struct populates some stuff correctly
        assert_eq!(new_user.username, String::from("my_username"));
        assert_eq!(new_user.password, None);

        // Make sure we can get the values again
        let mut connection = get_sql_connection(&test_pool).await;
        let rows = match sqlx::query("SELECT * FROM Users")
            .fetch_all(&mut connection)
            .await
        {
            Ok(raw_row) => raw_row,
            Err(_) => {
                panic!("Couldn't get rows during SELECT");
            }
        };
        assert_eq!(rows.len(), 1);
        let first_row = &rows[0];
        let first_username = first_row.get::<String, _>("username");
        let first_password = first_row.get::<Option<String>, _>("password");
        assert_eq!(first_username, String::from("my_username"));
        // And make sure there's no password
        assert_eq!(first_password, None);
    }

    #[actix_rt::test]
    async fn create_with_password() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let new_user = match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // Make sure the struct populates some stuff correctly
        assert_eq!(new_user.username, String::from("my_username"));

        // Make sure we can get the values again
        let mut connection = get_sql_connection(&test_pool).await;
        let rows = match sqlx::query("SELECT * FROM Users")
            .fetch_all(&mut connection)
            .await
        {
            Ok(raw_row) => raw_row,
            Err(_) => {
                panic!("Couldn't get rows during SELECT");
            }
        };
        assert_eq!(rows.len(), 1);
        let first_row = &rows[0];
        let first_username = first_row.get::<String, _>("username");
        let first_password = first_row.get::<Option<String>, _>("password");
        assert_eq!(first_username, String::from("my_username"));
        // Make sure the password returned by the struct is the same
        // as that inserted into the row
        let recovered_password = first_password.unwrap();
        assert_eq!(new_user.password.unwrap(), recovered_password);
        // And make sure what was inserted into the DB was correctly hashed
        let hashed_password = match PasswordHash::new(&recovered_password) {
            Ok(hashed_pass) => hashed_pass,
            Err(_) => {
                panic!("Could not recover hashed passsword from SQL DB!");
            }
        };
        assert!(Scrypt
            .verify_password(String::from("hunter2").as_bytes(), &hashed_password)
            .is_ok());
    }

    #[actix_rt::test]
    async fn create_no_dups() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the first user to set up the
        // conditions of this test
        match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(_) => {}
            Err(msg) => panic!("{}", msg),
        };
        // Attempt create another user with the same username. If this
        // succeeds, there's an issue with the implementation
        match User::create(
            String::from("my_username"),
            Some(String::from("mypassword123")),
            &test_pool,
        )
        .await
        {
            Ok(_) => {
                panic!("User::create allowed duplicate username insert!");
            }
            Err(_) => {}
        };
    }

    #[actix_rt::test]
    async fn with_username() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let new_user = match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // Let's get that user again using its username
        let user_with_username =
            match User::with_username(String::from("my_username"), &test_pool).await {
                Ok(user) => user,
                Err(msg) => panic!("{}", msg),
            };
        // Make sure we get the same data back
        assert_eq!(new_user, user_with_username);
        assert_eq!(new_user, user_with_username);
    }

    #[actix_rt::test]
    async fn has_password() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let user = match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        assert!(user.has_password(String::from("hunter2")));
        assert_eq!(user.has_password(String::from("password123")), false);
    }

    #[allow(unused_must_use)]
    #[actix_rt::test]
    async fn add_email_with_email() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let user = match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // Add an email for this user
        user.add_email(String::from("test@example.com"), false, &test_pool)
            .await;
        user.add_email(String::from("test2@example.com"), false, &test_pool)
            .await;
        // Get a user using an email
        let recovered_user1 =
            match User::with_email(String::from("test@example.com"), &test_pool).await {
                Ok(user) => user,
                Err(msg) => panic!("{}", msg),
            };
        // If both functions work properly, we have the same user
        assert_eq!(user, recovered_user1);
        // Get a user using an email
        let recovered_user2 =
            match User::with_email(String::from("test2@example.com"), &test_pool).await {
                Ok(user) => user,
                Err(msg) => panic!("{}", msg),
            };
        assert_eq!(user, recovered_user2);
        // Make sure that no user is retrieved from a non-existent email
        assert_eq!(
            User::with_email(String::from("some-random-email"), &test_pool)
                .await
                .is_ok(),
            false
        );
    }

    #[allow(unused_must_use)]
    #[actix_rt::test]
    async fn update_email() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let user = match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // Add an email for this user
        user.add_email(String::from("test@example.com"), false, &test_pool)
            .await;
        // Update it
        user.update_email(String::from("another-test@example.com"), &test_pool)
            .await;
        // Get a user using the new email
        let recovered_user =
            match User::with_email(String::from("another-test@example.com"), &test_pool).await {
                Ok(user) => user,
                Err(msg) => panic!("{}", msg),
            };
        // If all three functions work properly, we have the same user
        assert_eq!(user, recovered_user);
        // If we try to get the user with the previous email, there should be an error
        match User::with_email(String::from("test@example.com"), &test_pool).await {
            Ok(_) => panic!("User was incorrectly found with email!"),
            Err(_) => {}
        };
    }

    #[allow(unused_must_use)]
    #[actix_rt::test]
    async fn delete_email() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let user = match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // Add an email for this user
        user.add_email(String::from("test@example.com"), false, &test_pool)
            .await;
        // Delete it
        user.delete_email(String::from("test@example.com"), &test_pool)
            .await;
        // If we try to get the user with the email, there should be an error
        match User::with_email(String::from("test@example.com"), &test_pool).await {
            Ok(_) => panic!("User was incorrectly found with email!"),
            Err(_) => {}
        };
    }

    #[allow(unused_must_use)]
    #[actix_rt::test]
    async fn update_email_verification_status_is_verified() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let user = match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // Add an email for this user
        user.add_email(String::from("test@example.com"), false, &test_pool)
            .await;
        let email_verified = user
            .has_verified_email(String::from("test@example.com"), &test_pool)
            .await;
        assert_eq!(email_verified, false);
        // Update it
        user.update_email_verification_status(true, &test_pool)
            .await;
        let email_verified = user
            .has_verified_email(String::from("test@example.com"), &test_pool)
            .await;
        assert_eq!(email_verified, true);
    }

    #[allow(unused_must_use)]
    #[actix_rt::test]
    async fn add_eth_addr_with_eth_addr() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let user = match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // Add an ETH address for this user
        user.add_eth_address(
            String::from("0x2125E5963f17643461bE3067bA75c62dAC9f3D4A"),
            false,
            &test_pool,
        )
        .await;
        user.add_eth_address(
            String::from("0x0000000000000000000000000000000000000000"),
            false,
            &test_pool,
        )
        .await;
        // Get a user using an ETH address
        let recovered_user1 = match User::with_eth_address(
            String::from("0x0000000000000000000000000000000000000000"),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // If both functions work properly, we have the same user
        assert_eq!(user, recovered_user1);
        // Get a user using an ETH address
        let recovered_user2 = match User::with_eth_address(
            String::from("0x2125E5963f17643461bE3067bA75c62dAC9f3D4A"),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        assert_eq!(user, recovered_user2);
        // Make sure that no user is retrieved from a non-existent address
        assert_eq!(
            User::with_eth_address(String::from("some-random-address"), &test_pool,)
                .await
                .is_ok(),
            false
        );
    }

    #[allow(unused_must_use)]
    #[actix_rt::test]
    async fn update_eth_address() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let user = match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // Add an ETH address for this user
        user.add_eth_address(
            String::from("0x2125E5963f17643461bE3067bA75c62dAC9f3D4A"),
            false,
            &test_pool,
        )
        .await;
        // Update it
        user.update_eth_address(
            String::from("0x0000000000000000000000000000000000000000"),
            &test_pool,
        )
        .await;
        // Get a user using the new ETH address
        let recovered_user = match User::with_eth_address(
            String::from("0x0000000000000000000000000000000000000000"),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // If all three functions work properly, we have the same user
        assert_eq!(user, recovered_user);
        // If we try to get the user with the previous ETH address, there should be an error
        match User::with_eth_address(
            String::from("0x2125E5963f17643461bE3067bA75c62dAC9f3D4A"),
            &test_pool,
        )
        .await
        {
            Ok(_) => panic!("User was incorrectly found with Ethereum address!"),
            Err(_) => {}
        };
    }

    #[allow(unused_must_use)]
    #[actix_rt::test]
    async fn delete_eth_address() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let user = match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // Add an ETH address for this user
        user.add_eth_address(
            String::from("0x2125E5963f17643461bE3067bA75c62dAC9f3D4A"),
            false,
            &test_pool,
        )
        .await;
        // Delete it
        user.delete_eth_address(
            String::from("0x2125E5963f17643461bE3067bA75c62dAC9f3D4A"),
            &test_pool,
        )
        .await;
        // If we try to get the user with the ETH address, there should be an error
        match User::with_eth_address(
            String::from("0x2125E5963f17643461bE3067bA75c62dAC9f3D4A"),
            &test_pool,
        )
        .await
        {
            Ok(_) => panic!("User was incorrectly found with Ethereum address!"),
            Err(_) => {}
        };
    }

    #[allow(unused_must_use)]
    #[actix_rt::test]
    async fn update_eth_addr_verification_status_is_verified() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let user = match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // Add an ETH address for this user
        user.add_eth_address(
            String::from("0x2125E5963f17643461bE3067bA75c62dAC9f3D4A"),
            false,
            &test_pool,
        )
        .await;
        let eth_addr_verified = user
            .has_verified_eth_address(
                String::from("0x2125E5963f17643461bE3067bA75c62dAC9f3D4A"),
                &test_pool,
            )
            .await;
        assert_eq!(eth_addr_verified, false);
        // Update it
        user.update_eth_addr_verification_status(true, &test_pool)
            .await;
        let eth_addr_verified = user
            .has_verified_eth_address(
                String::from("0x2125E5963f17643461bE3067bA75c62dAC9f3D4A"),
                &test_pool,
            )
            .await;
        assert_eq!(eth_addr_verified, true);
    }

    #[allow(unused_must_use)]
    #[actix_rt::test]
    async fn add_login_token_with_login_token() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let user = match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // Add an email for this user
        user.add_login_token(String::from("asdfasdf"), &test_pool)
            .await;
        user.add_login_token(String::from(";lkj;lkj"), &test_pool)
            .await;
        // Get a user using a login token
        let recovered_user1 =
            match User::with_login_token(String::from("asdfasdf"), &test_pool).await {
                Ok(user) => user,
                Err(msg) => panic!("{}", msg),
            };
        // If both functions work properly, we have the same user
        assert_eq!(user, recovered_user1);
        // Get a user using a login token
        let recovered_user2 =
            match User::with_login_token(String::from(";lkj;lkj"), &test_pool).await {
                Ok(user) => user,
                Err(msg) => panic!("{}", msg),
            };
        assert_eq!(user, recovered_user2);
        // Make sure that no user is retrieved from a non-existent token
        assert_eq!(
            User::with_login_token(String::from("some-random-token"), &test_pool)
                .await
                .is_ok(),
            false
        );
    }

    #[allow(unused_must_use)]
    #[actix_rt::test]
    async fn delete_login_token() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let user = match User::create(
            String::from("my_username"),
            Some(String::from("hunter2")),
            &test_pool,
        )
        .await
        {
            Ok(user) => user,
            Err(msg) => panic!("{}", msg),
        };
        // Add a login token for this user
        user.add_login_token(String::from("asdfasdf"), &test_pool)
            .await;
        // Delete it
        user.delete_login_token(String::from("asdfasdf"), &test_pool)
            .await;
        // If we try to get the user with the login token, there should be an error
        match User::with_login_token(String::from("asdfasdf"), &test_pool).await {
            Ok(_) => panic!("User was incorrectly found with Ethereum address!"),
            Err(_) => {}
        };
    }
}
