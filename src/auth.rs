use std::future::{Ready, ready};

use actix_web::{Error, FromRequest, HttpRequest, error, web};

use crate::config::AppConfig;
use crate::jwt::decode_token;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: i32,
    pub username: String,
    pub role: String,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

impl FromRequest for AuthUser {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let cfg = match req.app_data::<web::Data<AppConfig>>() {
            Some(cfg) => cfg.get_ref(),
            None => return ready(Err(error::ErrorInternalServerError("missing app config"))),
        };

        let auth_header = match req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
        {
            Some(v) => v,
            None => {
                return ready(Err(error::ErrorUnauthorized(
                    "missing authorization header",
                )));
            }
        };

        let token = match auth_header.strip_prefix("Bearer ") {
            Some(v) if !v.is_empty() => v,
            _ => {
                return ready(Err(error::ErrorUnauthorized(
                    "invalid authorization format",
                )));
            }
        };

        let claims = match decode_token(cfg, token) {
            Ok(c) => c,
            Err(_) => return ready(Err(error::ErrorUnauthorized("invalid token"))),
        };

        if claims.token_type != "access" {
            return ready(Err(error::ErrorUnauthorized("invalid token type")));
        }

        ready(Ok(AuthUser {
            user_id: claims.sub,
            username: claims.username,
            role: claims.role,
        }))
    }
}
