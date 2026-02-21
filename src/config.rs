use std::env;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server_host: String,
    pub server_port: u16,
    pub database_url: String,
    pub jwt_secret: String,
    pub access_token_ttl_seconds: i64,
    pub refresh_token_ttl_seconds: i64,
}

impl AppConfig {
    pub fn load() -> anyhow::Result<Self> {
        let server_host = env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let server_port = env::var("SERVER_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(8080);
        let database_url = env::var("DATABASE_URL")?;
        let jwt_secret =
            env::var("JWT_SECRET").unwrap_or_else(|_| "changeme-jwt-secret".to_string());
        let access_token_ttl_seconds = env::var("JWT_ACCESS_TOKEN_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(900);
        let refresh_token_ttl_seconds = env::var("JWT_REFRESH_TOKEN_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(604800);

        Ok(Self {
            server_host,
            server_port,
            database_url,
            jwt_secret,
            access_token_ttl_seconds,
            refresh_token_ttl_seconds,
        })
    }
}
