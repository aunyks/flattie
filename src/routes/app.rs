use crate::models::User;
use crate::shared::{is_valid_email, is_valid_password, is_valid_username};
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use askama::Template;
use log::warn;
use serde::Deserialize;
use sqlx::AnyPool;

#[derive(Template)]
#[template(path = "myaccount.html")]
struct MyAccountPage {
    username: String,
    password_change_msg: Option<String>,
    password_change_error: Option<String>,
}

pub async fn myaccount_page(
    request: HttpRequest,
    db_connection: web::Data<AnyPool>,
) -> HttpResponse {
    match request.cookie("login_token") {
        Some(token_cookie) => {
            let login_token = String::from(token_cookie.value());
            match User::with_login_token(login_token.clone(), &db_connection).await {
                Ok(user) => {
                    let my_account_html = (MyAccountPage {
                        username: user.username().clone(),
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
                    warn!("Error while getting user from login token while navigating to main app page {}", msg);
                    HttpResponse::Found()
                        .header(
                            "Location",
                            crate::constants::auth::UNAUTHENTICATED_REDIRECT_DESTINATION,
                        )
                        .finish()
                }
            }
        }
        None => HttpResponse::Found()
            .header(
                "Location",
                crate::constants::auth::UNAUTHENTICATED_REDIRECT_DESTINATION,
            )
            .finish(),
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
    match request.cookie("login_token") {
        Some(token_cookie) => {
            let login_token = String::from(token_cookie.value());
            match User::with_login_token(login_token.clone(), &db_connection).await {
                Ok(mut user) => {
                    if !user.has_password(ch_pass_details.current_password.clone()) {
                        let my_account_html = (MyAccountPage {
                            username: user.username().clone(),
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
                                password_change_msg: Some(String::from(
                                    "Password changed successfully",
                                )),
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
                                password_change_msg: None,
                                password_change_error: Some(String::from(
                                    "Could not change password",
                                )),
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
                    warn!("Error while getting user from login token while navigating to main app page {}", msg);
                    HttpResponse::Found()
                        .header(
                            "Location",
                            crate::constants::auth::UNAUTHENTICATED_REDIRECT_DESTINATION,
                        )
                        .finish()
                }
            }
        }
        None => HttpResponse::Found()
            .header(
                "Location",
                crate::constants::auth::UNAUTHENTICATED_REDIRECT_DESTINATION,
            )
            .finish(),
    }
}
