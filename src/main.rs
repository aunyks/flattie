use actix_files::Files;
use actix_web::{web, App, HttpServer};
use env_logger::{Builder, Env};
use log::trace;
mod marketing;

const BINDING_ADDRESS: &str = "localhost:8080";

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let logger_env_config = Env::default().filter_or("FLATTIE_LOG_LEVEL", "flattie=trace");
    Builder::from_env(logger_env_config).init();

    trace!("Starting flattie server: http://{}", BINDING_ADDRESS);
    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(marketing::homepage))
            .service(Files::new("/static", "./static"))
    })
    .bind(BINDING_ADDRESS)?
    .run()
    .await
}
