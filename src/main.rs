use actix_files::Files;
use actix_web::{web, App, HttpServer};
use env_logger::{Builder, Env};
use log::{error, info};
use sqlx::any::AnyPoolOptions;
use std::{env, process::exit};
mod models;
mod routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let logger_env_config = Env::default().filter_or("FLATTIE_LOG_LEVEL", "flattie=trace");
    Builder::from_env(logger_env_config).init();

    let bind_address = match env::var("FLATTIE_BIND_ADDRESS") {
        Ok(address) => address,
        Err(_) => String::from("localhost:8080"),
    };

    let db_connection_url = match env::var("FLATTIE_SQL_CONNECTION_URL") {
        Ok(conn_url) => conn_url,
        Err(_) => {
            error!("SQL Connection URL (FLATTIE_SQL_CONNECTION_URL) is required but not provided!");
            exit(1)
        }
    };

    let db_connection_pool = match AnyPoolOptions::new()
        .max_connections(5)
        .connect(db_connection_url.as_str())
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

    info!("Starting flattie server: http://{}", bind_address);
    HttpServer::new(move || {
        App::new()
            .data(db_connection_pool.clone())
            .route("/", web::get().to(routes::marketing::homepage))
            .service(Files::new("/static", "./static"))
    })
    .bind(bind_address)?
    .run()
    .await
}
