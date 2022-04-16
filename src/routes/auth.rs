use crate::models::User;
use crate::shared::{is_valid_email, is_valid_password, is_valid_username};
use actix_web::http;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use askama::Template;
use log::{error, info, warn};
use serde::Deserialize;
use sqlx::AnyPool;

#[derive(Template)]
#[template(path = "signup.html")]
struct Signup {
    error_message: Option<String>,
}

pub async fn signup_page() -> HttpResponse {
    let signup_html = (Signup {
        error_message: None,
    })
    .render()
    .unwrap();
    HttpResponse::Ok()
        .content_type("text/html; charset=UTF-8")
        .body(signup_html)
}

#[derive(Deserialize)]
pub struct SignupDetails {
    username: String,
    email: String,
    password: String,
    confirm_password: String,
}

pub async fn signup_user(
    signup_details: web::Form<SignupDetails>,
    db_connection: web::Data<AnyPool>,
) -> HttpResponse {
    let mut signup_error = Signup {
        error_message: None,
    };

    if !is_valid_username(&signup_details.username) {
        signup_error.error_message = Some(String::from("Invalid username provided"));
        let signup_html = signup_error.render().unwrap();
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=UTF-8")
            .body(signup_html);
    }

    if User::with_username(signup_details.username.clone(), &db_connection)
        .await
        .is_ok()
    {
        signup_error.error_message = Some(String::from("Username already taken"));
        let signup_html = signup_error.render().unwrap();
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=UTF-8")
            .body(signup_html);
    }

    if !is_valid_email(&signup_details.email) {
        signup_error.error_message = Some(String::from("Invalid email provided"));
        let signup_html = signup_error.render().unwrap();
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=UTF-8")
            .body(signup_html);
    }

    if User::with_email(signup_details.email.clone(), &db_connection)
        .await
        .is_ok()
    {
        signup_error.error_message = Some(String::from("Email already in use"));
        let signup_html = signup_error.render().unwrap();
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=UTF-8")
            .body(signup_html);
    }

    if signup_details.password != signup_details.confirm_password {
        signup_error.error_message = Some(String::from("Password and confirm password must match"));
        let signup_html = signup_error.render().unwrap();
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=UTF-8")
            .body(signup_html);
    }

    if !is_valid_password(&signup_details.password) {
        signup_error.error_message = Some(String::from("Invalid password provided"));
        let signup_html = signup_error.render().unwrap();
        return HttpResponse::BadRequest()
            .content_type("text/html; charset=UTF-8")
            .body(signup_html);
    }

    match User::create(
        signup_details.username.clone(),
        Some(signup_details.password.clone()),
        &db_connection,
    )
    .await
    {
        Ok(user) => {
            if let Err(msg) = user
                .add_email(signup_details.email.clone(), false, &db_connection)
                .await
            {
                error!(
                    "Could not add email for newly created user {}.\nError: {}",
                    user, msg
                );
                signup_error.error_message =
                    Some(String::from("Unknown error occurred. Please try again"));
                let signup_html = signup_error.render().unwrap();
                return HttpResponse::InternalServerError()
                    .content_type("text/html; charset=UTF-8")
                    .body(signup_html);
            }
            let login_token = User::generate_login_token();
            if let Err(msg) = user
                .add_login_token(login_token.clone(), &db_connection)
                .await
            {
                error!(
                    "Could not create login token for {} during signup!\nError: {}",
                    &user, msg
                );
                signup_error.error_message =
                    Some(String::from("Unknown error occurred. Please try again"));
                let signup_html = signup_error.render().unwrap();
                return HttpResponse::InternalServerError()
                    .content_type("text/html; charset=UTF-8")
                    .body(signup_html);
            }
            info!("Created new user! {}", &user);
            HttpResponse::Found()
                .header(
                    "Set-Cookie",
                    format!(
                        "login_token={}; Secure; HttpOnly; SameSite=Strict; Max-Age=2600000",
                        login_token.clone()
                    ),
                )
                .header(
                    http::header::LOCATION,
                    crate::constants::auth::POST_SIGNUP_REDIRECT_DESTINATION,
                )
                .finish()
        }
        Err(msg) => {
            error!(
                "Error occurred while creating a new user during signup:\n{}",
                msg
            );
            signup_error.error_message =
                Some(String::from("Unknown error occurred. Please try again"));
            let signup_html = signup_error.render().unwrap();
            HttpResponse::InternalServerError()
                .content_type("text/html; charset=UTF-8")
                .body(signup_html)
        }
    }
}

#[derive(Template)]
#[template(path = "login.html")]
struct Login {
    error_message: Option<String>,
}

pub async fn login_page() -> HttpResponse {
    let login_html = (Login {
        error_message: None,
    })
    .render()
    .unwrap();
    HttpResponse::Ok()
        .content_type("text/html; charset=UTF-8")
        .body(login_html)
}

#[derive(Deserialize)]
pub struct LoginDetails {
    username_or_email: String,
    password: String,
}

pub async fn login_user(
    login_details: web::Form<LoginDetails>,
    db_connection: web::Data<AnyPool>,
) -> HttpResponse {
    let mut login_error = Login {
        error_message: None,
    };
    match is_valid_username(&login_details.username_or_email) {
        true => {
            // Valid username
            match User::with_username(login_details.username_or_email.clone(), &db_connection).await
            {
                Ok(user) => match user.has_password(login_details.password.clone()) {
                    true => {
                        let login_token = User::generate_login_token();
                        if let Err(msg) = user
                            .add_login_token(login_token.clone(), &db_connection)
                            .await
                        {
                            error!(
                                "Could not create login token for {} during login!\nError: {}",
                                &user, msg
                            );
                            login_error.error_message =
                                Some(String::from("Unknown error occurred. Please try again"));
                            let login_html = login_error.render().unwrap();
                            return HttpResponse::InternalServerError()
                                .content_type("text/html; charset=UTF-8")
                                .body(login_html);
                        }
                        info!("{} successfully logged in!", &user);
                        HttpResponse::Found()
                            .header(
                                "Set-Cookie",
                                format!(
                    "login_token={}; Secure; HttpOnly; SameSite=Strict; Max-Age=2600000",
                    login_token.clone()
                ),
                            )
                            .header(
                                http::header::LOCATION,
                                crate::constants::auth::POST_LOGIN_REDIRECT_DESTINATION,
                            )
                            .finish()
                    }
                    false => {
                        warn!("{} attempted login with incorrect password", &user);
                        login_error.error_message = Some(String::from("Password is incorrect"));
                        let login_html = login_error.render().unwrap();
                        HttpResponse::BadRequest()
                            .content_type("text/html; charset=UTF-8")
                            .body(login_html)
                    }
                },
                Err(msg) => {
                    warn!(
                        "User with unrecognized email {} attempted login\nError: {}",
                        &login_details.username_or_email, msg
                    );
                    login_error.error_message = Some(String::from(
                        "Username or email doesn't belong to an account",
                    ));
                    let login_html = login_error.render().unwrap();
                    HttpResponse::BadRequest()
                        .content_type("text/html; charset=UTF-8")
                        .body(login_html)
                }
            }
        }
        false => match is_valid_email(&login_details.username_or_email) {
            true => {
                // Valid email
                match User::with_email(login_details.username_or_email.clone(), &db_connection)
                    .await
                {
                    Ok(user) => match user.has_password(login_details.password.clone()) {
                        true => {
                            let login_token = User::generate_login_token();
                            if let Err(msg) = user
                                .add_login_token(login_token.clone(), &db_connection)
                                .await
                            {
                                error!(
                                    "Could not create login token for {} during login!\nError: {}",
                                    &user, msg
                                );
                                login_error.error_message =
                                    Some(String::from("Unknown error occurred. Please try again"));
                                let login_html = login_error.render().unwrap();
                                return HttpResponse::InternalServerError()
                                    .content_type("text/html; charset=UTF-8")
                                    .body(login_html);
                            }
                            HttpResponse::Found()
                                .header(
                                    "Set-Cookie",
                                    format!(
                        "login_token={}; Secure; HttpOnly; SameSite=Strict; Max-Age=2600000",
                        login_token.clone()
                    ),
                                )
                                .header(
                                    http::header::LOCATION,
                                    crate::constants::auth::POST_LOGIN_REDIRECT_DESTINATION,
                                )
                                .finish()
                        }
                        false => {
                            warn!("{} attempted login with incorrect password", &user);
                            login_error.error_message = Some(String::from("Password is incorrect"));
                            let login_html = login_error.render().unwrap();
                            HttpResponse::BadRequest()
                                .content_type("text/html; charset=UTF-8")
                                .body(login_html)
                        }
                    },
                    Err(msg) => {
                        warn!(
                            "User with unrecognized email {} attempted login\nError: {}",
                            &login_details.username_or_email, msg
                        );
                        login_error.error_message = Some(String::from(
                            "Username or email doesn't belong to an account",
                        ));
                        let login_html = login_error.render().unwrap();
                        HttpResponse::BadRequest()
                            .content_type("text/html; charset=UTF-8")
                            .body(login_html)
                    }
                }
            }
            // Not a valid username or email
            false => {
                login_error.error_message =
                    Some(String::from("Invalid username or email provided"));
                let login_html = login_error.render().unwrap();
                HttpResponse::BadRequest()
                    .content_type("text/html; charset=UTF-8")
                    .body(login_html)
            }
        },
    }
}

pub async fn logout_user(request: HttpRequest, db_connection: web::Data<AnyPool>) -> HttpResponse {
    match request.cookie("login_token") {
        Some(token_cookie) => {
            let login_token = String::from(token_cookie.value());
            match User::with_login_token(login_token.clone(), &db_connection).await {
                Ok(user) => match user.delete_login_token(login_token, &db_connection).await {
                    Ok(_) => HttpResponse::Found()
                        .header(
                            http::header::LOCATION,
                            crate::constants::auth::UNAUTHENTICATED_REDIRECT_DESTINATION,
                        )
                        .header(
                            "Set-Cookie",
                            "login_token=none; Secure; HttpOnly; SameSite=Strict; Max-Age=1",
                        )
                        .finish(),
                    Err(msg) => {
                        error!("Could not delete login token of {}.\nError: {}", &user, msg);
                        HttpResponse::InternalServerError().finish()
                    }
                },
                Err(_) => HttpResponse::BadRequest().finish(),
            }
        }
        None => HttpResponse::BadRequest().finish(),
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::models::testing_helpers::create_user_tables;
    use crate::shared::testing_helpers::create_test_sql_pool;
    use actix_web::body::Body::Bytes;
    use actix_web::http::StatusCode;
    use actix_web::test::TestRequest;
    use regex::Regex;

    #[actix_rt::test]
    async fn test_signup_page() {
        let signup_response = signup_page().await;

        assert_eq!(StatusCode::OK, signup_response.status());

        let headers = signup_response.headers();
        assert_eq!(
            "text/html; charset=UTF-8",
            headers.get("content-type").unwrap()
        );

        let response_body = signup_response.body().as_ref().unwrap();
        match response_body {
            Bytes(body_bytes) => {
                let body = String::from(std::str::from_utf8(body_bytes).unwrap());
                assert!(body.contains("Sign up"))
            }
            _ => {
                panic!("Response body enum was not Bytes variant!");
            }
        }
    }

    #[actix_rt::test]
    async fn test_signup_user() {
        let test_pool = create_test_sql_pool().await;
        create_user_tables(&test_pool).await;
        let signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("username"),
                email: String::from("email@a.co"),
                password: String::from("pasddfafafafaff"),
                confirm_password: String::from("pasddfafafafaff"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;

        assert_eq!(StatusCode::FOUND, signup_response.status());

        let headers = signup_response.headers();
        let set_cookie_regex =
            Regex::new("login_token=.{20,24}; Secure; HttpOnly; SameSite=Strict; Max-Age=2600000")
                .unwrap();
        let set_cookie_header_value = headers.get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie_regex.is_match(set_cookie_header_value));

        let location_header_value = headers.get("location").unwrap().to_str().unwrap();
        assert_eq!("/app/my-account", location_header_value);

        let recovered_user = User::with_username(String::from("username"), &test_pool)
            .await
            .unwrap();

        assert!(recovered_user.has_password(String::from("pasddfafafafaff")));

        let email_assets = recovered_user.emails(&test_pool).await.unwrap();
        assert_eq!(1, email_assets.len());

        let email = &email_assets[0].asset;
        assert_eq!("email@a.co", email);
    }

    #[actix_rt::test]
    async fn test_signup_user_no_duplicate_usernames() {
        let test_pool = create_test_sql_pool().await;
        create_user_tables(&test_pool).await;
        let signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("username"),
                email: String::from("email@a.co"),
                password: String::from("pasddfafafafaff"),
                confirm_password: String::from("pasddfafafafaff"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;

        assert_eq!(StatusCode::FOUND, signup_response.status());

        let headers = signup_response.headers();
        let set_cookie_regex =
            Regex::new("login_token=.{20,24}; Secure; HttpOnly; SameSite=Strict; Max-Age=2600000")
                .unwrap();
        let set_cookie_header_value = headers.get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie_regex.is_match(set_cookie_header_value));

        let location_header_value = headers.get("location").unwrap().to_str().unwrap();
        assert_eq!("/app/my-account", location_header_value);

        let recovered_user = User::with_username(String::from("username"), &test_pool)
            .await
            .unwrap();

        assert!(recovered_user.has_password(String::from("pasddfafafafaff")));

        let email_assets = recovered_user.emails(&test_pool).await.unwrap();
        assert_eq!(1, email_assets.len());

        let email = &email_assets[0].asset;
        assert_eq!("email@a.co", email);

        let second_signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("username"),
                email: String::from("email+b@a.co"),
                password: String::from("seconduserpass"),
                confirm_password: String::from("seconduserpass"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;
        assert_eq!(StatusCode::BAD_REQUEST, second_signup_response.status());

        let response_body = second_signup_response.body().as_ref().unwrap();
        match response_body {
            Bytes(body_bytes) => {
                let body = String::from(std::str::from_utf8(body_bytes).unwrap());
                assert!(body.contains("Username already taken"))
            }
            _ => {
                panic!("Response body enum was not Bytes variant!");
            }
        }
    }

    #[actix_rt::test]
    async fn test_signup_user_no_duplicate_emails() {
        let test_pool = create_test_sql_pool().await;
        create_user_tables(&test_pool).await;
        let signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("username"),
                email: String::from("email@a.co"),
                password: String::from("pasddfafafafaff"),
                confirm_password: String::from("pasddfafafafaff"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;

        assert_eq!(StatusCode::FOUND, signup_response.status());

        let headers = signup_response.headers();
        let set_cookie_regex =
            Regex::new("login_token=.{20,24}; Secure; HttpOnly; SameSite=Strict; Max-Age=2600000")
                .unwrap();
        let set_cookie_header_value = headers.get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie_regex.is_match(set_cookie_header_value));

        let location_header_value = headers.get("location").unwrap().to_str().unwrap();
        assert_eq!("/app/my-account", location_header_value);

        let recovered_user = User::with_username(String::from("username"), &test_pool)
            .await
            .unwrap();

        assert!(recovered_user.has_password(String::from("pasddfafafafaff")));

        let email_assets = recovered_user.emails(&test_pool).await.unwrap();
        assert_eq!(1, email_assets.len());

        let email = &email_assets[0].asset;
        assert_eq!("email@a.co", email);

        let second_signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("username2"),
                email: String::from("email@a.co"),
                password: String::from("seconduserpass"),
                confirm_password: String::from("seconduserpass"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;
        assert_eq!(StatusCode::BAD_REQUEST, second_signup_response.status());

        let response_body = second_signup_response.body().as_ref().unwrap();
        match response_body {
            Bytes(body_bytes) => {
                let body = String::from(std::str::from_utf8(body_bytes).unwrap());
                assert!(body.contains("Email already in use"))
            }
            _ => {
                panic!("Response body enum was not Bytes variant!");
            }
        }
    }

    #[actix_rt::test]
    async fn test_signup_user_too_short_password() {
        let test_pool = create_test_sql_pool().await;
        create_user_tables(&test_pool).await;
        let signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("username"),
                email: String::from("email@a.co"),
                password: String::from("pasd"),
                confirm_password: String::from("pasd"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;

        assert_eq!(StatusCode::BAD_REQUEST, signup_response.status());

        let response_body = signup_response.body().as_ref().unwrap();
        match response_body {
            Bytes(body_bytes) => {
                let body = String::from(std::str::from_utf8(body_bytes).unwrap());
                assert!(body.contains("Invalid password provided"))
            }
            _ => {
                panic!("Response body enum was not Bytes variant!");
            }
        };

        // Make sure user was never created
        assert!(User::with_username(String::from("username"), &test_pool)
            .await
            .is_err());
        assert!(User::with_email(String::from("email@a.co"), &test_pool)
            .await
            .is_err());
    }

    #[actix_rt::test]
    async fn test_signup_user_unconfirmed_password() {
        let test_pool = create_test_sql_pool().await;
        create_user_tables(&test_pool).await;
        let signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("username"),
                email: String::from("email@a.co"),
                password: String::from("pasd"),
                confirm_password: String::from("yyyy"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;

        assert_eq!(StatusCode::BAD_REQUEST, signup_response.status());

        let response_body = signup_response.body().as_ref().unwrap();
        match response_body {
            Bytes(body_bytes) => {
                let body = String::from(std::str::from_utf8(body_bytes).unwrap());
                assert!(body.contains("Password and confirm password must match"))
            }
            _ => {
                panic!("Response body enum was not Bytes variant!");
            }
        };

        // Make sure user was never created
        assert!(User::with_username(String::from("username"), &test_pool)
            .await
            .is_err());
        assert!(User::with_email(String::from("email@a.co"), &test_pool)
            .await
            .is_err());
    }

    #[actix_rt::test]
    async fn test_signup_user_invalid_email() {
        let test_pool = create_test_sql_pool().await;
        create_user_tables(&test_pool).await;
        let signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("username"),
                email: String::from("email@a"),
                password: String::from("pasddfafafafaff"),
                confirm_password: String::from("pasddfafafafaff"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;

        assert_eq!(StatusCode::BAD_REQUEST, signup_response.status());

        let response_body = signup_response.body().as_ref().unwrap();
        match response_body {
            Bytes(body_bytes) => {
                let body = String::from(std::str::from_utf8(body_bytes).unwrap());
                assert!(body.contains("Invalid email provided"))
            }
            _ => {
                panic!("Response body enum was not Bytes variant!");
            }
        };

        // Make sure user was never created
        assert!(User::with_username(String::from("username"), &test_pool)
            .await
            .is_err());
        assert!(User::with_email(String::from("email@a"), &test_pool)
            .await
            .is_err());
    }

    #[actix_rt::test]
    async fn test_signup_user_invalid_username() {
        let test_pool = create_test_sql_pool().await;
        create_user_tables(&test_pool).await;
        let signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("usern^me"),
                email: String::from("email@a.co"),
                password: String::from("pasddfafafafaff"),
                confirm_password: String::from("pasddfafafafaff"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;

        assert_eq!(StatusCode::BAD_REQUEST, signup_response.status());

        let response_body = signup_response.body().as_ref().unwrap();
        match response_body {
            Bytes(body_bytes) => {
                let body = String::from(std::str::from_utf8(body_bytes).unwrap());
                assert!(body.contains("Invalid username provided"))
            }
            _ => {
                panic!("Response body enum was not Bytes variant!");
            }
        };

        // Make sure user was never created
        assert!(User::with_username(String::from("usern^me"), &test_pool)
            .await
            .is_err());
        assert!(User::with_email(String::from("email@a.co"), &test_pool)
            .await
            .is_err());
    }

    #[actix_rt::test]
    async fn test_logout() {
        let test_pool = create_test_sql_pool().await;
        create_user_tables(&test_pool).await;

        // Sign up
        let signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("username"),
                email: String::from("email@a.co"),
                password: String::from("pasddfafafafaff"),
                confirm_password: String::from("pasddfafafafaff"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;

        let signup_headers = signup_response.headers();

        let login_token_regex = Regex::new(
            "login_token=(?P<token>.{20,24}); Secure; HttpOnly; SameSite=Strict; Max-Age=2600000",
        )
        .unwrap();
        let set_cookie_header_value = signup_headers.get("set-cookie").unwrap().to_str().unwrap();
        let set_cookie_header_captures =
            login_token_regex.captures(set_cookie_header_value).unwrap();
        let login_token = set_cookie_header_captures.name("token").unwrap().as_str();

        let recovered_user = User::with_username(String::from("username"), &test_pool)
            .await
            .unwrap();
        assert!(recovered_user.has_password(String::from("pasddfafafafaff")));
        let email_assets = recovered_user.emails(&test_pool).await.unwrap();
        assert_eq!(1, email_assets.len());
        let email = &email_assets[0].asset;
        assert_eq!("email@a.co", email);

        // Log back out
        let logout_req = TestRequest::default()
            .header("Cookie", format!("login_token={}", login_token))
            .to_http_request();
        let logout_response = logout_user(logout_req, web::Data::new(test_pool.clone())).await;
        assert_eq!(StatusCode::FOUND, logout_response.status());

        let logout_headers = logout_response.headers();

        let post_logout_redirect_location =
            logout_headers.get("location").unwrap().to_str().unwrap();
        assert_eq!("/", post_logout_redirect_location);

        let post_logout_login_token = logout_headers.get("set-cookie").unwrap().to_str().unwrap();
        assert_eq!(
            "login_token=none; Secure; HttpOnly; SameSite=Strict; Max-Age=1",
            post_logout_login_token
        );
    }

    #[actix_rt::test]
    async fn test_login_page() {
        let login_response = login_page().await;

        assert_eq!(StatusCode::OK, login_response.status());

        let headers = login_response.headers();
        assert_eq!(
            "text/html; charset=UTF-8",
            headers.get("content-type").unwrap()
        );

        let response_body = login_response.body().as_ref().unwrap();
        match response_body {
            Bytes(body_bytes) => {
                let body = String::from(std::str::from_utf8(body_bytes).unwrap());
                assert!(body.contains("Log in"))
            }
            _ => {
                panic!("Response body enum was not Bytes variant!");
            }
        }
    }

    #[actix_rt::test]
    async fn test_login_user_with_username() {
        let test_pool = create_test_sql_pool().await;
        create_user_tables(&test_pool).await;

        // Sign up
        let signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("username"),
                email: String::from("email@a.co"),
                password: String::from("pasddfafafafaff"),
                confirm_password: String::from("pasddfafafafaff"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;

        let signup_headers = signup_response.headers();

        let login_token_regex = Regex::new(
            "login_token=(?P<token>.{20,24}); Secure; HttpOnly; SameSite=Strict; Max-Age=2600000",
        )
        .unwrap();
        let set_cookie_header_value = signup_headers.get("set-cookie").unwrap().to_str().unwrap();
        let set_cookie_header_captures =
            login_token_regex.captures(set_cookie_header_value).unwrap();
        let login_token = set_cookie_header_captures.name("token").unwrap().as_str();

        let recovered_user = User::with_username(String::from("username"), &test_pool)
            .await
            .unwrap();
        assert!(recovered_user.has_password(String::from("pasddfafafafaff")));
        let email_assets = recovered_user.emails(&test_pool).await.unwrap();
        assert_eq!(1, email_assets.len());
        let email = &email_assets[0].asset;
        assert_eq!("email@a.co", email);

        // Log back out
        let logout_req = TestRequest::default()
            .header("Cookie", format!("login_token={}", login_token))
            .to_http_request();
        let logout_response = logout_user(logout_req, web::Data::new(test_pool.clone())).await;
        let logout_headers = logout_response.headers();
        let post_logout_login_token = logout_headers.get("set-cookie").unwrap().to_str().unwrap();

        assert_eq!(
            "login_token=none; Secure; HttpOnly; SameSite=Strict; Max-Age=1",
            post_logout_login_token
        );

        // Log back in again
        let login_response = login_user(
            web::Form(LoginDetails {
                username_or_email: String::from("username"),
                password: String::from("pasddfafafafaff"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;
        assert_eq!(StatusCode::FOUND, login_response.status());

        let login_headers = login_response.headers();
        let headers = login_response.headers();
        let set_cookie_regex =
            Regex::new("login_token=.{20,24}; Secure; HttpOnly; SameSite=Strict; Max-Age=2600000")
                .unwrap();
        let set_cookie_header_value = login_headers.get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie_regex.is_match(set_cookie_header_value));

        let location_header_value = headers.get("location").unwrap().to_str().unwrap();
        assert_eq!("/app/my-account", location_header_value);
    }

    #[actix_rt::test]
    async fn test_login_user_with_email() {
        let test_pool = create_test_sql_pool().await;
        create_user_tables(&test_pool).await;

        // Sign up
        let signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("username"),
                email: String::from("email@a.co"),
                password: String::from("pasddfafafafaff"),
                confirm_password: String::from("pasddfafafafaff"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;

        let signup_headers = signup_response.headers();

        let login_token_regex = Regex::new(
            "login_token=(?P<token>.{20,24}); Secure; HttpOnly; SameSite=Strict; Max-Age=2600000",
        )
        .unwrap();
        let set_cookie_header_value = signup_headers.get("set-cookie").unwrap().to_str().unwrap();
        let set_cookie_header_captures =
            login_token_regex.captures(set_cookie_header_value).unwrap();
        let login_token = set_cookie_header_captures.name("token").unwrap().as_str();

        let recovered_user = User::with_username(String::from("username"), &test_pool)
            .await
            .unwrap();
        assert!(recovered_user.has_password(String::from("pasddfafafafaff")));
        let email_assets = recovered_user.emails(&test_pool).await.unwrap();
        assert_eq!(1, email_assets.len());
        let email = &email_assets[0].asset;
        assert_eq!("email@a.co", email);

        // Log back out
        let logout_req = TestRequest::default()
            .header("Cookie", format!("login_token={}", login_token))
            .to_http_request();
        let logout_response = logout_user(logout_req, web::Data::new(test_pool.clone())).await;
        let logout_headers = logout_response.headers();
        let post_logout_login_token = logout_headers.get("set-cookie").unwrap().to_str().unwrap();

        assert_eq!(
            "login_token=none; Secure; HttpOnly; SameSite=Strict; Max-Age=1",
            post_logout_login_token
        );

        // Log back in again
        let login_response = login_user(
            web::Form(LoginDetails {
                username_or_email: String::from("email@a.co"),
                password: String::from("pasddfafafafaff"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;
        assert_eq!(StatusCode::FOUND, login_response.status());

        let login_headers = login_response.headers();
        let headers = login_response.headers();
        let set_cookie_regex =
            Regex::new("login_token=.{20,24}; Secure; HttpOnly; SameSite=Strict; Max-Age=2600000")
                .unwrap();
        let set_cookie_header_value = login_headers.get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie_regex.is_match(set_cookie_header_value));

        let location_header_value = headers.get("location").unwrap().to_str().unwrap();
        assert_eq!("/app/my-account", location_header_value);
    }

    #[actix_rt::test]
    async fn test_login_user_incorrect_password() {
        let test_pool = create_test_sql_pool().await;
        create_user_tables(&test_pool).await;

        // Sign up
        let signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("username"),
                email: String::from("email@a.co"),
                password: String::from("pasddfafafafaff"),
                confirm_password: String::from("pasddfafafafaff"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;

        let signup_headers = signup_response.headers();

        let login_token_regex = Regex::new(
            "login_token=(?P<token>.{20,24}); Secure; HttpOnly; SameSite=Strict; Max-Age=2600000",
        )
        .unwrap();
        let set_cookie_header_value = signup_headers.get("set-cookie").unwrap().to_str().unwrap();
        let set_cookie_header_captures =
            login_token_regex.captures(set_cookie_header_value).unwrap();
        let login_token = set_cookie_header_captures.name("token").unwrap().as_str();

        let recovered_user = User::with_username(String::from("username"), &test_pool)
            .await
            .unwrap();
        assert!(recovered_user.has_password(String::from("pasddfafafafaff")));
        let email_assets = recovered_user.emails(&test_pool).await.unwrap();
        assert_eq!(1, email_assets.len());
        let email = &email_assets[0].asset;
        assert_eq!("email@a.co", email);

        // Log back out
        let logout_req = TestRequest::default()
            .header("Cookie", format!("login_token={}", login_token))
            .to_http_request();
        let logout_response = logout_user(logout_req, web::Data::new(test_pool.clone())).await;
        let logout_headers = logout_response.headers();
        let post_logout_login_token = logout_headers.get("set-cookie").unwrap().to_str().unwrap();

        assert_eq!(
            "login_token=none; Secure; HttpOnly; SameSite=Strict; Max-Age=1",
            post_logout_login_token
        );

        // Log back in again
        let login_response = login_user(
            web::Form(LoginDetails {
                username_or_email: String::from("username"),
                password: String::from("pasddfa"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;
        assert_eq!(StatusCode::BAD_REQUEST, login_response.status());

        let response_body = login_response.body().as_ref().unwrap();
        match response_body {
            Bytes(body_bytes) => {
                let body = String::from(std::str::from_utf8(body_bytes).unwrap());
                assert!(body.contains("Password is incorrect"))
            }
            _ => {
                panic!("Response body enum was not Bytes variant!");
            }
        }
    }

    #[actix_rt::test]
    async fn test_login_user_incorrect_username_or_email() {
        let test_pool = create_test_sql_pool().await;
        create_user_tables(&test_pool).await;

        // Sign up
        let signup_response = signup_user(
            web::Form(SignupDetails {
                username: String::from("username"),
                email: String::from("email@a.co"),
                password: String::from("pasddfafafafaff"),
                confirm_password: String::from("pasddfafafafaff"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;

        let signup_headers = signup_response.headers();

        let login_token_regex = Regex::new(
            "login_token=(?P<token>.{20,24}); Secure; HttpOnly; SameSite=Strict; Max-Age=2600000",
        )
        .unwrap();
        let set_cookie_header_value = signup_headers.get("set-cookie").unwrap().to_str().unwrap();
        let set_cookie_header_captures =
            login_token_regex.captures(set_cookie_header_value).unwrap();
        let login_token = set_cookie_header_captures.name("token").unwrap().as_str();

        let recovered_user = User::with_username(String::from("username"), &test_pool)
            .await
            .unwrap();
        assert!(recovered_user.has_password(String::from("pasddfafafafaff")));
        let email_assets = recovered_user.emails(&test_pool).await.unwrap();
        assert_eq!(1, email_assets.len());
        let email = &email_assets[0].asset;
        assert_eq!("email@a.co", email);

        // Log back out
        let logout_req = TestRequest::default()
            .header("Cookie", format!("login_token={}", login_token))
            .to_http_request();
        let logout_response = logout_user(logout_req, web::Data::new(test_pool.clone())).await;
        let logout_headers = logout_response.headers();
        let post_logout_login_token = logout_headers.get("set-cookie").unwrap().to_str().unwrap();

        assert_eq!(
            "login_token=none; Secure; HttpOnly; SameSite=Strict; Max-Age=1",
            post_logout_login_token
        );

        // Log back in again
        let login_response = login_user(
            web::Form(LoginDetails {
                username_or_email: String::from("unrecognized_username"),
                password: String::from("pasddfafafafaff"),
            }),
            web::Data::new(test_pool.clone()),
        )
        .await;
        assert_eq!(StatusCode::BAD_REQUEST, login_response.status());

        let response_body = login_response.body().as_ref().unwrap();
        match response_body {
            Bytes(body_bytes) => {
                let body = String::from(std::str::from_utf8(body_bytes).unwrap());
                assert!(body.contains("Username or email doesn&#x27;t belong to an account"))
            }
            _ => {
                panic!("Response body enum was not Bytes variant!");
            }
        }
    }
}
