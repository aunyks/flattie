use log::{debug, error, trace};
use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt,
};
use sqlx::{AnyPool, Row};

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
            Err(_) => {
                error!("Could not acquire SQL connection from pool!");
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        let row = match sqlx::query("SELECT * FROM Users WHERE username = ?")
            .bind(&username)
            .fetch_one(&mut sql_connection)
            .await
        {
            Ok(raw_row) => raw_row,
            Err(_) => {
                error!("Could not fetch user by username!");
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
    async fn test_user_create_no_password() {
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
    async fn test_user_create_with_password() {
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
    async fn test_user_create_no_dups() {
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
    async fn test_user_with_username() {
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
        assert_eq!(new_user.username, user_with_username.username);
        assert_eq!(new_user.password, user_with_username.password);
    }

    #[actix_rt::test]
    async fn test_user_has_password() {
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
    }
}
