use axum::http::header;
use axum::response::{Html, IntoResponse};

const INDEX_HTML: &str = include_str!("static/index.html");

pub async fn serve_index() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-cache")], Html(INDEX_HTML))
}
