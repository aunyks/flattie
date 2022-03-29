use crate::models::User;
use crate::shared::{is_valid_email, is_valid_password, is_valid_username};
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use askama::Template;
use log::{error, warn};
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
        return HttpResponse::Ok()
            .content_type("text/html; charset=UTF-8")
            .body(signup_html);
    }

    if User::with_username(signup_details.username.clone(), &db_connection)
        .await
        .is_ok()
    {
        signup_error.error_message = Some(String::from("Username already taken"));
        let signup_html = signup_error.render().unwrap();
        return HttpResponse::Ok()
            .content_type("text/html; charset=UTF-8")
            .body(signup_html);
    }

    if !is_valid_email(&signup_details.email) {
        signup_error.error_message = Some(String::from("Invalid email provided"));
        let signup_html = signup_error.render().unwrap();
        return HttpResponse::Ok()
            .content_type("text/html; charset=UTF-8")
            .body(signup_html);
    }

    if User::with_email(signup_details.email.clone(), &db_connection)
        .await
        .is_ok()
    {
        signup_error.error_message = Some(String::from("Email already in use"));
        let signup_html = signup_error.render().unwrap();
        return HttpResponse::Ok()
            .content_type("text/html; charset=UTF-8")
            .body(signup_html);
    }

    if !is_valid_password(&signup_details.password) {
        signup_error.error_message = Some(String::from("Invalid password provided"));
        let signup_html = signup_error.render().unwrap();
        return HttpResponse::Ok()
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
                return HttpResponse::Ok()
                    .content_type("text/html; charset=UTF-8")
                    .body(signup_html);
            }
            let login_token = User::generate_login_token();
            if let Err(msg) = user
                .add_login_token(login_token.clone(), &db_connection)
                .await
            {
                warn!(
                    "Could not create login token for {} during signup!\nError: {}",
                    &user, msg
                );
                signup_error.error_message =
                    Some(String::from("Unknown error occurred. Please try again"));
                let signup_html = signup_error.render().unwrap();
                return HttpResponse::Ok()
                    .content_type("text/html; charset=UTF-8")
                    .body(signup_html);
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
                    "Location",
                    crate::constants::auth::POST_SIGNUP_REDIRECT_DESTINATION,
                )
                .finish()
        }
        Err(msg) => {
            warn!(
                "Error occurred while creating a new user during signup:\n{}",
                msg
            );
            signup_error.error_message =
                Some(String::from("Unknown error occurred. Please try again"));
            let signup_html = signup_error.render().unwrap();
            HttpResponse::Ok()
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
                            warn!(
                                "Could not create login token for {} during login!\nError: {}",
                                &user, msg
                            );
                            login_error.error_message =
                                Some(String::from("Unknown error occurred. Please try again"));
                            let login_html = login_error.render().unwrap();
                            return HttpResponse::Ok()
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
                                "Location",
                                crate::constants::auth::POST_LOGIN_REDIRECT_DESTINATION,
                            )
                            .finish()
                    }
                    false => {
                        warn!("{} attempted login with incorrect password", &user);
                        login_error.error_message = Some(String::from("Password is incorrect"));
                        let login_html = login_error.render().unwrap();
                        HttpResponse::Ok()
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
                    HttpResponse::Ok()
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
                                warn!(
                                    "Could not create login token for {} during login!\nError: {}",
                                    &user, msg
                                );
                                login_error.error_message =
                                    Some(String::from("Unknown error occurred. Please try again"));
                                let login_html = login_error.render().unwrap();
                                return HttpResponse::Ok()
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
                                    "Location",
                                    crate::constants::auth::POST_LOGIN_REDIRECT_DESTINATION,
                                )
                                .finish()
                        }
                        false => {
                            warn!("{} attempted login with incorrect password", &user);
                            login_error.error_message = Some(String::from("Password is incorrect"));
                            let login_html = login_error.render().unwrap();
                            HttpResponse::Ok()
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
                        HttpResponse::Ok()
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
                HttpResponse::Ok()
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
                            "Location",
                            crate::constants::auth::UNAUTHENTICATED_REDIRECT_DESTINATION,
                        )
                        .header(
                            "Set-Cookie",
                            "login_token=none; Secure; HttpOnly; SameSite=Strict; Max-Age=1",
                        )
                        .finish(),
                    Err(msg) => {
                        warn!("Could not delete login token of {}.\nError: {}", &user, msg);
                        HttpResponse::InternalServerError().finish()
                    }
                },
                Err(_) => HttpResponse::BadRequest().finish(),
            }
        }
        None => HttpResponse::BadRequest().finish(),
    }
}
