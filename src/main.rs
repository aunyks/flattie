// use actix_cors::Cors;
use actix_files::Files;
use actix_web::{web, App, HttpServer};
use env_logger::{Builder, Env};
use log::{error, info, warn};
use routes::{app, auth, marketing};
use sqlx::postgres::PgPoolOptions;
use std::{env, process::exit};
mod constants;
mod middleware;
mod models;
mod routes;
mod shared;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let logger_env_config = Env::default().filter_or("FLATTIE_LOG_LEVEL", "flattie=trace");
    Builder::from_env(logger_env_config).init();

    let bind_address = match env::var("FLATTIE_BIND_ADDRESS") {
        Ok(address) => address,
        Err(_) => String::from("localhost:8080"),
    };

    let mut db_is_in_memory = false;
    let db_connection_url = match env::var("FLATTIE_SQL_CONNECTION_URL") {
        Ok(conn_url) => conn_url,
        Err(_) => {
            warn!("No SQL connection URL provided! Using in-memory SQLite DB.");
            db_is_in_memory = true;
            String::from("sqlite::memory:")
        }
    };

    let db_connection_pool = match PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_connection_url)
        .await
    {
        Ok(pool) => pool,
        Err(_) => {
            error!(
                "Could not create connection pool to SQL database {}!",
                db_connection_url
            );
            exit(1)
        }
    };

    // If we're using an in-memory DB, we need to set up our tables.
    // We only do this for in-memory DBs, because we can be certain that
    // no tables have already been created. The same cannot be said of DBs
    // given to us via a URL.
    if db_is_in_memory {
        sqlx::query(include_str!("../migrations/create-user-tables.sql"))
            .execute(&db_connection_pool)
            .await
            .expect("Could not set up user tables for in-memory SQL DB!");
    }

    info!("Starting flattie server: http://{}", bind_address);
    HttpServer::new(move || {
        App::new()
            .data(db_connection_pool.clone())
            // Uncomment the below to work around CORS issues in dev
            // .wrap(Cors::default().allow_any_origin())
            .service(Files::new("/static", "./static"))
            // Marketing
            .route("/", web::get().to(marketing::homepage))
            // Auth
            .route("/signup", web::get().to(auth::signup_page))
            .route("/signup", web::post().to(auth::signup_user))
            .route("/login", web::get().to(auth::login_page))
            .route("/login", web::post().to(auth::login_user))
            .route("/logout", web::post().to(auth::logout_user))
            // Random, mostly for debugging / example
            .route("/ws", web::get().to(app::echo_ws))
            // Behind auth wall
            .service(
                web::scope("/app/")
                    .wrap(middleware::IsAuthenticated)
                    .route("/my-account", web::get().to(app::myaccount_page))
                    .route("/add-email", web::post().to(app::add_email))
                    .route("/remove-email", web::post().to(app::remove_email))
                    .route("/change-password", web::post().to(app::change_password)),
            )
    })
    .bind(bind_address)?
    .run()
    .await
}
