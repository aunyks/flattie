use crate::models::ExternalAsset;
use crate::models::User;
use crate::shared::{is_valid_email, is_valid_password};
use actix_web::http;
use actix_web::{cookie::Cookie, web, HttpMessage, HttpRequest, HttpResponse};
use askama::Template;
use log::{error, warn};
use serde::Deserialize;
use sqlx::AnyPool;

#[derive(Template)]
#[template(path = "myaccount.html")]
struct MyAccountPage {
    username: String,
    emails: Vec<ExternalAsset>,
    password_change_msg: Option<String>,
    password_change_error: Option<String>,
}

pub async fn myaccount_page(
    request: HttpRequest,
    db_connection: web::Data<AnyPool>,
) -> HttpResponse {
    let login_token = String::from(
        request
            .cookie("login_token")
            .unwrap_or(Cookie::new("login_token", ""))
            .value(),
    );
    match User::with_login_token(login_token.clone(), &db_connection).await {
        Ok(user) => {
            let emails = match user.emails(&db_connection).await {
                Ok(email_vec) => email_vec,
                Err(msg) => {
                    error!(
                        "Error occurred while getting {} emails.\nError: {}",
                        user, msg
                    );
                    return HttpResponse::InternalServerError().finish();
                }
            };
            let my_account_html = (MyAccountPage {
                username: user.username().clone(),
                emails: emails,
                password_change_msg: None,
                password_change_error: None,
            })
            .render()
            .unwrap();
            HttpResponse::Ok()
                .content_type("text/html; charset=UTF-8")
                .body(my_account_html)
        }
        Err(msg) => {
            warn!(
                "Error while getting user from login token while navigating to main app page {}",
                msg
            );
            HttpResponse::Found()
                .header(
                    http::header::LOCATION,
                    crate::constants::auth::UNAUTHENTICATED_REDIRECT_DESTINATION,
                )
                .finish()
        }
    }
}

#[derive(Deserialize)]
pub struct ChangePassword {
    current_password: String,
    new_password: String,
}

pub async fn change_password(
    request: HttpRequest,
    db_connection: web::Data<AnyPool>,
    ch_pass_details: web::Form<ChangePassword>,
) -> HttpResponse {
    let login_token = String::from(
        request
            .cookie("login_token")
            .unwrap_or(Cookie::new("login_token", ""))
            .value(),
    );
    match User::with_login_token(login_token.clone(), &db_connection).await {
        Ok(mut user) => {
            let emails = match user.emails(&db_connection).await {
                Ok(email_vec) => email_vec,
                Err(msg) => {
                    error!(
                        "Error occurred while getting {} emails.\nError: {}",
                        user, msg
                    );
                    return HttpResponse::InternalServerError().finish();
                }
            };
            if !user.has_password(ch_pass_details.current_password.clone()) {
                let my_account_html = (MyAccountPage {
                    username: user.username().clone(),
                    emails: emails,
                    password_change_msg: None,
                    password_change_error: Some(String::from("Current password incorrect")),
                })
                .render()
                .unwrap();
                return HttpResponse::Ok()
                    .content_type("text/html; charset=UTF-8")
                    .body(my_account_html);
            }
            if !is_valid_password(&ch_pass_details.new_password) {
                let my_account_html = (MyAccountPage {
                    username: user.username().clone(),
                    emails: emails,
                    password_change_msg: None,
                    password_change_error: Some(String::from(
                        "New password invalid. Password not changed",
                    )),
                })
                .render()
                .unwrap();
                return HttpResponse::Ok()
                    .content_type("text/html; charset=UTF-8")
                    .body(my_account_html);
            }
            match user
                .update_password(ch_pass_details.new_password.clone(), &db_connection)
                .await
            {
                Ok(_) => {
                    let my_account_html = (MyAccountPage {
                        username: user.username().clone(),
                        emails,
                        password_change_msg: Some(String::from("Password changed successfully")),
                        password_change_error: None,
                    })
                    .render()
                    .unwrap();
                    HttpResponse::Ok()
                        .content_type("text/html; charset=UTF-8")
                        .body(my_account_html)
                }
                Err(msg) => {
                    warn!(
                        "Error occurred while changing user password.\nError: {}",
                        msg
                    );
                    let my_account_html = (MyAccountPage {
                        username: user.username().clone(),
                        emails,
                        password_change_msg: None,
                        password_change_error: Some(String::from("Could not change password")),
                    })
                    .render()
                    .unwrap();
                    HttpResponse::Ok()
                        .content_type("text/html; charset=UTF-8")
                        .body(my_account_html)
                }
            }
        }
        Err(msg) => {
            warn!(
                "Error while getting user from login token while changing password {}",
                msg
            );
            HttpResponse::Found()
                .header(
                    http::header::LOCATION,
                    crate::constants::auth::UNAUTHENTICATED_REDIRECT_DESTINATION,
                )
                .finish()
        }
    }
}

#[derive(Deserialize)]
pub struct AddEmail {
    password: String,
    new_email: String,
}

pub async fn add_email(
    request: HttpRequest,
    db_connection: web::Data<AnyPool>,
    add_email_details: web::Form<AddEmail>,
) -> HttpResponse {
    let login_token = String::from(
        request
            .cookie("login_token")
            .unwrap_or(Cookie::new("login_token", ""))
            .value(),
    );
    match User::with_login_token(login_token.clone(), &db_connection).await {
        Ok(user) => {
            if !user.has_password(add_email_details.password.clone()) {
                warn!("{} used incorrect password while adding new email", user);
                return HttpResponse::Found()
                    .header(http::header::LOCATION, "/app/my-account")
                    .finish();
            }
            if !is_valid_email(&add_email_details.new_email) {
                warn!("{} tried adding invalid email", user);
                return HttpResponse::Found()
                    .header(http::header::LOCATION, "/app/my-account")
                    .finish();
            }
            if let Err(msg) = user
                .add_email(add_email_details.new_email.clone(), false, &db_connection)
                .await
            {
                error!(
                    "Error occurred while adding {} email.\nError: {}",
                    user, msg
                );
            }
            HttpResponse::Found()
                .header(http::header::LOCATION, "/app/my-account")
                .finish()
        }
        Err(msg) => {
            warn!(
                "Error while getting user from login token while adding email {}",
                msg
            );
            HttpResponse::Found()
                .header(
                    http::header::LOCATION,
                    crate::constants::auth::UNAUTHENTICATED_REDIRECT_DESTINATION,
                )
                .finish()
        }
    }
}

#[derive(Deserialize)]
pub struct RemoveEmail {
    email: String,
    password: String,
}

pub async fn remove_email(
    request: HttpRequest,
    db_connection: web::Data<AnyPool>,
    remove_email_details: web::Form<RemoveEmail>,
) -> HttpResponse {
    let login_token = String::from(
        request
            .cookie("login_token")
            .unwrap_or(Cookie::new("login_token", ""))
            .value(),
    );
    match User::with_login_token(login_token.clone(), &db_connection).await {
        Ok(user) => {
            if !user.has_password(remove_email_details.password.clone()) {
                warn!("{} used incorrect password while adding new email", user);
                return HttpResponse::Found()
                    .header(http::header::LOCATION, "/app/my-account")
                    .finish();
            }
            match user.emails(&db_connection).await {
                Ok(email_vec) => {
                    if email_vec.len() == 1 {
                        warn!("{} tried deleting their only email", user);
                        return HttpResponse::Found()
                            .header(http::header::LOCATION, "/app/my-account")
                            .finish();
                    }
                }
                Err(_) => {
                    error!(
                        "Error occurred while getting {} emails during removing email",
                        user
                    );
                    return HttpResponse::Found()
                        .header(http::header::LOCATION, "/app/my-account")
                        .finish();
                }
            }
            if let Err(msg) = user
                .delete_email(remove_email_details.email.clone(), &db_connection)
                .await
            {
                error!(
                    "Error occurred while removing {} email.\nError: {}",
                    user, msg
                );
            }
            HttpResponse::Found()
                .header(http::header::LOCATION, "/app/my-account")
                .finish()
        }
        Err(msg) => {
            warn!(
                "Error while getting user from login token while removing email {}",
                msg
            );
            HttpResponse::Found()
                .header(
                    http::header::LOCATION,
                    crate::constants::auth::UNAUTHENTICATED_REDIRECT_DESTINATION,
                )
                .finish()
        }
    }
}
