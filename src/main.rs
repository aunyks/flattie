use actix_files::Files;
use actix_web::{web, App, HttpServer};
use env_logger::{Builder, Env};
use log::trace;
use std::env;
mod routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let logger_env_config = Env::default().filter_or("FLATTIE_LOG_LEVEL", "flattie=trace");
    Builder::from_env(logger_env_config).init();

    let bind_address = match env::var("FLATTIE_BIND_ADDRESS") {
        Ok(address) => address,
        Err(_) => String::from("localhost:8080"),
    };

    trace!("Starting flattie server: http://{}", bind_address);
    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(routes::marketing::homepage))
            .service(Files::new("/static", "./static"))
    })
    .bind(bind_address)?
    .run()
    .await
}
