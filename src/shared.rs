use regex::Regex;

pub fn is_valid_username(username: &String) -> bool {
    let invalid_chars = [
        "'", "\"", "/", "\\", ",", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "?", ";", ":",
        "[", "]", "{", "}", "|", " ", "\t", "\n", "\r",
    ];
    let mut invalid_char_index = 0;
    username.len() > 0
        && username.len() < 36
        && loop {
            if invalid_char_index < invalid_chars.len() {
                if username.contains(invalid_chars[invalid_char_index]) {
                    return false;
                }
                invalid_char_index += 1;
            } else {
                return true;
            }
        }
}

pub fn is_valid_email(email: &String) -> bool {
    let email_expression = Regex::new(r"^\S+@\S+\.\S+$").unwrap();
    email_expression.is_match(email)
}

pub fn is_valid_password(plaintext_password: &String) -> bool {
    plaintext_password.len() >= 8 && plaintext_password.len() < 101
}

#[cfg(test)]
pub mod testing_helpers {
    use sqlx::any::AnyPoolOptions;
    use sqlx::pool::PoolConnection;
    use sqlx::AnyPool;

    pub async fn create_test_sql_pool() -> AnyPool {
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

    pub async fn get_sql_connection(conn_pool: &AnyPool) -> PoolConnection<sqlx::Any> {
        match conn_pool.acquire().await {
            Ok(conn) => conn,
            Err(_) => {
                panic!("Could not individual connection to SQL database!");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_username() {
        assert_eq!(is_valid_username(&String::from("virgilhawkins")), true);
        assert_eq!(is_valid_username(&String::from("v1rgilh4wkins")), true);
        assert_eq!(is_valid_username(&String::from("v(rgilh4wkins")), false);
        assert_eq!(is_valid_username(&String::from("v\\rrgilh4wkins")), false);
        assert_eq!(is_valid_username(&String::from("v1rgilh4wkin$")), false);
    }

    #[test]
    fn test_is_valid_email() {
        assert_eq!(is_valid_email(&String::from("a@example.com")), true);
        assert_eq!(is_valid_email(&String::from("a+b@example.com")), true);
        // assert_eq!(is_valid_email(&String::from("a+b+c@example.com")), false);
        assert_eq!(is_valid_email(&String::from("a+b@")), false);
        assert_eq!(is_valid_email(&String::from("a+b")), false);
        assert_eq!(is_valid_email(&String::from("a")), false);
    }
}
