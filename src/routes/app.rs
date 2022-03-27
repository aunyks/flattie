use crate::models::User;
use crate::shared::{is_valid_email, is_valid_password, is_valid_username};
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use askama::Template;
use log::error;
use serde::Deserialize;
use sqlx::AnyPool;

#[derive(Template)]
#[template(path = "app.html")]
struct AppMainPage {
    username: String,
}

pub async fn main(request: HttpRequest, db_connection: web::Data<AnyPool>) -> HttpResponse {
    match request.cookie("login_token") {
        Some(token_cookie) => {
            let login_token = String::from(token_cookie.value());
            match User::with_login_token(login_token.clone(), &db_connection).await {
                Ok(user) => {
                    let main_html = (AppMainPage {
                        username: user.username().clone(),
                    })
                    .render()
                    .unwrap();
                    HttpResponse::Ok()
                        .content_type("text/html; charset=UTF-8")
                        .body(main_html)
                }
                Err(msg) => {
                    error!("Error while getting user from login token while navigating to main app page {}", msg);
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
