use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::config::AppConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i32,
    pub username: String,
    pub role: String,
    pub token_type: String,
    pub iat: i64,
    pub exp: i64,
}

pub fn generate_token_pair(
    cfg: &AppConfig,
    user_id: i32,
    username: &str,
    role: &str,
) -> anyhow::Result<(String, String)> {
    let now = Utc::now().timestamp();
    let access_claims = Claims {
        sub: user_id,
        username: username.to_string(),
        role: role.to_string(),
        token_type: "access".to_string(),
        iat: now,
        exp: now + cfg.access_token_ttl_seconds,
    };

    let refresh_claims = Claims {
        sub: user_id,
        username: username.to_string(),
        role: role.to_string(),
        token_type: "refresh".to_string(),
        iat: now,
        exp: now + cfg.refresh_token_ttl_seconds,
    };

    let secret = cfg.jwt_secret.as_bytes();
    let access_token = encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(secret),
    )?;
    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(secret),
    )?;
    Ok((access_token, refresh_token))
}

pub fn decode_token(cfg: &AppConfig, token: &str) -> anyhow::Result<Claims> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(data.claims)
}
