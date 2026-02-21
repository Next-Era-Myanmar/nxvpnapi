use utoipa::OpenApi;

use crate::handlers::{ErrorResponse, HealthResponse};
use crate::models::{
    AssignParentKeyRequest, ChangeMyPasswordRequest, CreateOutlineKeyRequest, CreateUserRequest,
    LoginRequest, MyOutlineKeyQuery, OutlineKeyFilterQuery, OutlineKeyResponse,
    RefreshTokenRequest, ResetPasswordRequest, TokenPairResponse, UpdateOutlineKeyRequest,
    UpdateUserRequest, UserResponse,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::health,
        crate::handlers::list_users,
        crate::handlers::create_user,
        crate::handlers::update_user,
        crate::handlers::reset_user_password,
        crate::handlers::me,
        crate::handlers::change_my_password,
        crate::handlers::create_outline_key,
        crate::handlers::list_outline_keys,
        crate::handlers::get_outline_key,
        crate::handlers::update_outline_key,
        crate::handlers::delete_outline_key,
        crate::handlers::assign_parent_key_to_user,
        crate::handlers::my_outline_keys,
        crate::handlers::login,
        crate::handlers::refresh
    ),
    components(
        schemas(
            HealthResponse,
            ErrorResponse,
            CreateUserRequest,
            UserResponse,
            LoginRequest,
            RefreshTokenRequest,
            TokenPairResponse,
            UpdateUserRequest,
            ResetPasswordRequest,
            ChangeMyPasswordRequest,
            CreateOutlineKeyRequest,
            UpdateOutlineKeyRequest,
            OutlineKeyResponse,
            AssignParentKeyRequest,
            OutlineKeyFilterQuery,
            MyOutlineKeyQuery
        )
    ),
    tags(
        (name = "system", description = "System endpoints"),
        (name = "users", description = "User CRUD example endpoints"),
        (name = "auth", description = "Authentication endpoints"),
        (name = "outline-keys", description = "Outline key management endpoints")
    ),
    info(
        title = "NXVPN API",
        version = "0.1.0",
        description = "Baseline Actix-Web API with Scalar docs and Diesel ORM"
    ),
    servers(
        (url = "/", description = "Current host")
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

use utoipa::Modify;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}
