use actix_web::HttpResponse;
use askama::Template;

#[derive(Template)]
#[template(path = "index.html")]
struct Homepage {}

pub async fn homepage() -> HttpResponse {
    let homepage_html = (Homepage {}).render().unwrap();
    HttpResponse::Ok()
        .content_type("text/html; charset=UTF-8")
        .body(homepage_html)
}
