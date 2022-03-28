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
    plaintext_password.len() > 8 && plaintext_password.len() < 101
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
