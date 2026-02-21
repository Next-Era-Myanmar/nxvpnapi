use actix_cors::Cors;
use actix_files::{Files, NamedFile};
use actix_web::{App, HttpResponse, HttpServer, Responder, get, web};
use dotenvy::dotenv;
use nxvpnapi::config::AppConfig;
use nxvpnapi::db::establish_pool;
use nxvpnapi::{handlers, openapi::ApiDoc};
use scalar_api_reference::{get_asset_with_mime, scalar_html_default};
use serde_json::json;
use utoipa::OpenApi;

#[get("/openapi.json")]
async fn openapi_json() -> impl Responder {
    HttpResponse::Ok().json(ApiDoc::openapi())
}

async fn scalar_html_handler(config: web::Data<serde_json::Value>) -> impl Responder {
    let html = scalar_html_default(&config).replace(
        "<title>Scalar API Reference</title>",
        "<title>NXVPN API</title>",
    );
    HttpResponse::Ok().content_type("text/html").body(html)
}

async fn scalar_asset_handler(path: web::Path<String>) -> impl Responder {
    let asset_name = path.into_inner();
    if let Some((mime_type, content)) = get_asset_with_mime(&asset_name) {
        HttpResponse::Ok().content_type(mime_type).body(content)
    } else {
        HttpResponse::NotFound().finish()
    }
}

async fn admin_index() -> std::io::Result<NamedFile> {
    NamedFile::open(concat!(env!("CARGO_MANIFEST_DIR"), "/admin-panel/index.html"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let cfg = AppConfig::load().expect("failed to load config");
    let pool = establish_pool(&cfg.database_url).expect("failed to initialize database pool");

    let scalar_config = json!({
        "url": "/openapi.json",
        "theme": "deepSpace",
        "layout": "modern",
    });

    let host = cfg.server_host.clone();
    let port = cfg.server_port;
    println!("Server started at http://{}:{}", host, port);
    println!("Scalar docs at http://{}:{}/scalar", host, port);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(cfg.clone()))
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(scalar_config.clone()))
            .service(handlers::health)
            .service(handlers::list_users)
            .service(handlers::create_user)
            .service(handlers::update_user)
            .service(handlers::reset_user_password)
            .service(handlers::me)
            .service(handlers::change_my_password)
            .service(handlers::create_outline_key)
            .service(handlers::list_outline_keys)
            .service(handlers::get_outline_key)
            .service(handlers::update_outline_key)
            .service(handlers::delete_outline_key)
            .service(handlers::assign_parent_key_to_user)
            .service(handlers::my_outline_keys)
            .service(handlers::login)
            .service(handlers::refresh)
            .service(openapi_json)
            .route("/admin", web::get().to(admin_index))
            .service(Files::new(
                "/admin",
                concat!(env!("CARGO_MANIFEST_DIR"), "/admin-panel"),
            ))
            .route("/scalar", web::get().to(scalar_html_handler))
            .route("/scalar/{asset:.*}", web::get().to(scalar_asset_handler))
            .default_service(web::route().to(HttpResponse::NotFound))
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}
