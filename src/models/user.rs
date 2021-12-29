use log::error;
use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt,
};
use sqlx::AnyPool;

pub struct User {
    username: String,
    password: String,
}

impl User {
    pub async fn create(
        username: String,
        password: String,
        conn_pool: &AnyPool,
    ) -> Result<User, &str> {
        let mut sql_connection = match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(_) => {
                error!("Could not acquire SQL connection from pool!");
                return Err("Could not acquire SQL connection from pool!");
            }
        };
        let salt = SaltString::generate(&mut OsRng);
        // Password string format:
        // https://github.com/P-H-C/phc-string-format/blob/5f1e4ec633845d43776849f503f8ce8314b5290c/phc-sf-spec.md
        let hashed_password = match Scrypt.hash_password(password.as_bytes(), &salt) {
            Ok(hashed_pass) => hashed_pass.to_string(),
            Err(_) => {
                error!("Could not hash password!");
                return Err("Could not hash password!");
            }
        };
        match sqlx::query("INSERT INTO Users (username, password) VALUES (?, ?)")
            .bind(username.as_str())
            .bind(hashed_password.clone())
            .execute(&mut sql_connection)
            .await
        {
            Ok(raw_row) => raw_row,
            Err(_) => {
                error!("User creation SQL query failed!");
                return Err("User creation SQL query failed!");
            }
        };

        Ok(User {
            username: username,
            password: hashed_password,
        })
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
            Err(_) => {
                panic!("Could not execute user creation SQL commands!");
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
    async fn test_user_create() {
        // Get a pool to connect to an in-memory DB
        let test_pool = create_test_sql_pool().await;
        // Create our user table
        create_user_tables(&test_pool).await;

        // Create the user using the model
        let new_user = match User::create(
            String::from("my_username"),
            String::from("hunter2"),
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
        let first_password = first_row.get::<String, _>("password");
        assert_eq!(first_username, String::from("my_username"));
        // Make sure the password returned by the struct is the same
        // as that inserted into the row
        assert_eq!(new_user.password, first_password);
        // And make sure what was inserted into the DB was correctly hashed
        let hashed_password = match PasswordHash::new(&first_password) {
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
            String::from("hunter2"),
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
            String::from("mypassword123"),
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
}
