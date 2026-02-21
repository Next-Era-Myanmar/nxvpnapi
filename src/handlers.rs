use actix_web::{HttpResponse, Responder, get, patch, post, web};
use chrono::Utc;
use diesel::prelude::*;
use serde::Serialize;

use crate::auth::AuthUser;
use crate::config::AppConfig;
use crate::crypto::{hash_password, verify_password};
use crate::db::PgPool;
use crate::jwt::{decode_token, generate_token_pair};
use crate::models::{
    AssignParentKeyRequest, ChangeMyPasswordRequest, CreateOutlineKeyRequest, CreateUserRequest,
    LoginRequest, MyOutlineKeyQuery, NewOutlineKey, NewUser, OutlineKey, OutlineKeyFilterQuery,
    OutlineKeyResponse, RefreshTokenRequest, ResetPasswordRequest, TokenPairResponse,
    UpdateOutlineKeyRequest, UpdateUserRequest, User, UserResponse,
};
use crate::schema::{outline_keys, user_access_keys, users};

#[derive(Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    pub message: String,
}

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, body = HealthResponse)
    ),
    tag = "system"
)]
#[get("/health")]
pub async fn health() -> impl Responder {
    HttpResponse::Ok().json(HealthResponse { status: "ok" })
}

#[utoipa::path(
    get,
    path = "/users",
    responses(
        (status = 200, body = [UserResponse]),
        (status = 500, body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "users"
)]
#[get("/users")]
pub async fn list_users(auth: AuthUser, pool: web::Data<PgPool>) -> impl Responder {
    if !auth.is_admin() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            message: "admin only route".to_string(),
        });
    }

    let pool = pool.clone();
    let query = web::block(move || {
        let mut conn = pool.get()?;
        users::table
            .select(User::as_select())
            .order(users::created_at.desc())
            .limit(100)
            .load::<User>(&mut conn)
            .map_err(anyhow::Error::from)
    })
    .await;

    match query {
        Ok(Ok(rows)) => {
            let payload: Vec<UserResponse> = rows.into_iter().map(UserResponse::from).collect();
            HttpResponse::Ok().json(payload)
        }
        _ => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to fetch users".to_string(),
        }),
    }
}

#[utoipa::path(
    post,
    path = "/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, body = UserResponse),
        (status = 400, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "users"
)]
#[post("/users")]
pub async fn create_user(
    auth: AuthUser,
    pool: web::Data<PgPool>,
    payload: web::Json<CreateUserRequest>,
) -> impl Responder {
    if !auth.is_admin() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            message: "admin only route".to_string(),
        });
    }

    let request = payload.into_inner();
    if request.username.trim().is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            message: "username is required".to_string(),
        });
    }
    if request.password.trim().is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            message: "password is required".to_string(),
        });
    }
    if let Some(user_type) = &request.type_ {
        if user_type != "admin" && user_type != "user" {
            return HttpResponse::BadRequest().json(ErrorResponse {
                message: "type must be admin or user".to_string(),
            });
        }
    }

    let password_hashed = match hash_password(&request.password) {
        Ok(hash) => hash,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                message: "failed to hash password".to_string(),
            });
        }
    };

    let pool = pool.clone();
    let query = web::block(move || {
        let mut conn = pool.get()?;
        let new_user = NewUser {
            display_name: request.display_name,
            username: request.username,
            password_hashed,
            contact_email: request.contact_email,
            expired_at: request.expired_at,
            refresh_token: None,
        };
        let user_type = request.type_.unwrap_or_else(|| "user".to_string());

        diesel::insert_into(users::table)
            .values((&new_user, users::type_.eq(user_type)))
            .returning(User::as_returning())
            .get_result::<User>(&mut conn)
            .map_err(anyhow::Error::from)
    })
    .await;

    match query {
        Ok(Ok(user)) => HttpResponse::Created().json(UserResponse::from(user)),
        Ok(Err(err)) if err.to_string().contains("duplicate key value") => {
            HttpResponse::BadRequest().json(ErrorResponse {
                message: "username already exists".to_string(),
            })
        }
        _ => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to create user".to_string(),
        }),
    }
}

#[utoipa::path(
    patch,
    path = "/users/{id}",
    request_body = UpdateUserRequest,
    params(
        ("id" = i32, Path, description = "User id")
    ),
    responses(
        (status = 200, body = UserResponse),
        (status = 400, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "users"
)]
#[patch("/users/{id}")]
pub async fn update_user(
    auth: AuthUser,
    path: web::Path<i32>,
    pool: web::Data<PgPool>,
    payload: web::Json<UpdateUserRequest>,
) -> impl Responder {
    if !auth.is_admin() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            message: "admin only route".to_string(),
        });
    }

    let user_id = path.into_inner();
    let req = payload.into_inner();
    if let Some(user_type) = &req.type_ {
        if user_type != "admin" && user_type != "user" {
            return HttpResponse::BadRequest().json(ErrorResponse {
                message: "type must be admin or user".to_string(),
            });
        }
    }

    let query_pool = pool.clone();
    let query = web::block(move || {
        let mut conn = query_pool.get()?;
        let maybe_user = users::table
            .filter(users::id.eq(user_id))
            .select(User::as_select())
            .first::<User>(&mut conn)
            .optional()
            .map_err(anyhow::Error::from)?;

        let existing = match maybe_user {
            Some(u) => u,
            None => return Ok::<Option<User>, anyhow::Error>(None),
        };

        let next_display_name = req.display_name.or(existing.display_name);
        let next_contact_email = req.contact_email.or(existing.contact_email);
        let next_expired_at = req.expired_at.or(existing.expired_at);
        let next_type = req.type_.unwrap_or(existing.type_);

        let updated = diesel::update(users::table.filter(users::id.eq(user_id)))
            .set((
                users::display_name.eq(next_display_name),
                users::contact_email.eq(next_contact_email),
                users::expired_at.eq(next_expired_at),
                users::type_.eq(next_type),
            ))
            .returning(User::as_returning())
            .get_result::<User>(&mut conn)
            .map_err(anyhow::Error::from)?;
        Ok::<Option<User>, anyhow::Error>(Some(updated))
    })
    .await;

    match query {
        Ok(Ok(Some(user))) => HttpResponse::Ok().json(UserResponse::from(user)),
        Ok(Ok(None)) => HttpResponse::NotFound().json(ErrorResponse {
            message: "user not found".to_string(),
        }),
        _ => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to update user".to_string(),
        }),
    }
}

#[utoipa::path(
    post,
    path = "/users/{id}/reset-password",
    request_body = ResetPasswordRequest,
    params(
        ("id" = i32, Path, description = "User id")
    ),
    responses(
        (status = 200, body = UserResponse),
        (status = 400, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "users"
)]
#[post("/users/{id}/reset-password")]
pub async fn reset_user_password(
    auth: AuthUser,
    path: web::Path<i32>,
    pool: web::Data<PgPool>,
    payload: web::Json<ResetPasswordRequest>,
) -> impl Responder {
    if !auth.is_admin() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            message: "admin only route".to_string(),
        });
    }

    let req = payload.into_inner();
    if req.new_password.trim().is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            message: "new_password is required".to_string(),
        });
    }
    let hashed = match hash_password(&req.new_password) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                message: "failed to hash password".to_string(),
            });
        }
    };

    let user_id = path.into_inner();
    let query_pool = pool.clone();
    let query = web::block(move || {
        let mut conn = query_pool.get()?;
        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set(users::password_hashed.eq(hashed))
            .returning(User::as_returning())
            .get_result::<User>(&mut conn)
            .optional()
            .map_err(anyhow::Error::from)
    })
    .await;

    match query {
        Ok(Ok(Some(user))) => HttpResponse::Ok().json(UserResponse::from(user)),
        Ok(Ok(None)) => HttpResponse::NotFound().json(ErrorResponse {
            message: "user not found".to_string(),
        }),
        _ => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to reset password".to_string(),
        }),
    }
}

#[utoipa::path(
    get,
    path = "/me",
    responses(
        (status = 200, body = UserResponse),
        (status = 404, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "users"
)]
#[get("/me")]
pub async fn me(auth: AuthUser, pool: web::Data<PgPool>) -> impl Responder {
    let query_pool = pool.clone();
    let user_id = auth.user_id;
    let query = web::block(move || {
        let mut conn = query_pool.get()?;
        users::table
            .filter(users::id.eq(user_id))
            .select(User::as_select())
            .first::<User>(&mut conn)
            .optional()
            .map_err(anyhow::Error::from)
    })
    .await;

    match query {
        Ok(Ok(Some(user))) => HttpResponse::Ok().json(UserResponse::from(user)),
        Ok(Ok(None)) => HttpResponse::NotFound().json(ErrorResponse {
            message: "user not found".to_string(),
        }),
        _ => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to load profile".to_string(),
        }),
    }
}

#[utoipa::path(
    post,
    path = "/me/change-password",
    request_body = ChangeMyPasswordRequest,
    responses(
        (status = 200, body = UserResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "users"
)]
#[post("/me/change-password")]
pub async fn change_my_password(
    auth: AuthUser,
    pool: web::Data<PgPool>,
    payload: web::Json<ChangeMyPasswordRequest>,
) -> impl Responder {
    let req = payload.into_inner();
    if req.current_password.trim().is_empty() || req.new_password.trim().is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            message: "current_password and new_password are required".to_string(),
        });
    }

    let query_pool = pool.clone();
    let user_id = auth.user_id;
    let user_query = web::block(move || {
        let mut conn = query_pool.get()?;
        users::table
            .filter(users::id.eq(user_id))
            .select(User::as_select())
            .first::<User>(&mut conn)
            .optional()
            .map_err(anyhow::Error::from)
    })
    .await;

    let user = match user_query {
        Ok(Ok(Some(user))) => user,
        Ok(Ok(None)) => {
            return HttpResponse::NotFound().json(ErrorResponse {
                message: "user not found".to_string(),
            });
        }
        _ => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                message: "failed to change password".to_string(),
            });
        }
    };

    let valid = match verify_password(&req.current_password, &user.password_hashed) {
        Ok(v) => v,
        Err(_) => false,
    };
    if !valid {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            message: "current password is incorrect".to_string(),
        });
    }

    let hashed = match hash_password(&req.new_password) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                message: "failed to hash password".to_string(),
            });
        }
    };

    let query_pool = pool.clone();
    let user_id = auth.user_id;
    let query = web::block(move || {
        let mut conn = query_pool.get()?;
        diesel::update(users::table.filter(users::id.eq(user_id)))
            .set(users::password_hashed.eq(hashed))
            .returning(User::as_returning())
            .get_result::<User>(&mut conn)
            .optional()
            .map_err(anyhow::Error::from)
    })
    .await;

    match query {
        Ok(Ok(Some(updated))) => HttpResponse::Ok().json(UserResponse::from(updated)),
        Ok(Ok(None)) => HttpResponse::NotFound().json(ErrorResponse {
            message: "user not found".to_string(),
        }),
        _ => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to change password".to_string(),
        }),
    }
}

#[utoipa::path(
    post,
    path = "/outline-keys",
    request_body = CreateOutlineKeyRequest,
    responses(
        (status = 201, body = OutlineKeyResponse),
        (status = 400, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "outline-keys"
)]
#[post("/outline-keys")]
pub async fn create_outline_key(
    auth: AuthUser,
    pool: web::Data<PgPool>,
    payload: web::Json<CreateOutlineKeyRequest>,
) -> impl Responder {
    if !auth.is_admin() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            message: "admin only route".to_string(),
        });
    }

    let req = payload.into_inner();
    if req.name.trim().is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            message: "name is required".to_string(),
        });
    }

    let query_pool = pool.clone();
    let query = web::block(move || {
        let mut conn = query_pool.get()?;
        let new_key = NewOutlineKey {
            name: req.name,
            outline_key: req.outline_key,
            country: req.country,
            parent_id: req.parent_id,
        };

        diesel::insert_into(outline_keys::table)
            .values(&new_key)
            .returning(OutlineKey::as_returning())
            .get_result::<OutlineKey>(&mut conn)
            .map_err(anyhow::Error::from)
    })
    .await;

    match query {
        Ok(Ok(key)) => HttpResponse::Created().json(OutlineKeyResponse::from(key)),
        _ => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to create outline key".to_string(),
        }),
    }
}

#[utoipa::path(
    get,
    path = "/outline-keys",
    params(
        ("parent_id" = Option<i32>, Query, description = "Filter by parent key id"),
        ("parents_only" = Option<bool>, Query, description = "When true, return only parent keys")
    ),
    responses(
        (status = 200, body = [OutlineKeyResponse]),
        (status = 403, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "outline-keys"
)]
#[get("/outline-keys")]
pub async fn list_outline_keys(
    auth: AuthUser,
    query: web::Query<OutlineKeyFilterQuery>,
    pool: web::Data<PgPool>,
) -> impl Responder {
    if !auth.is_admin() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            message: "admin only route".to_string(),
        });
    }

    let filter = query.into_inner();
    let query_pool = pool.clone();
    let query = web::block(move || {
        let mut conn = query_pool.get()?;
        let mut stmt = outline_keys::table.into_boxed();
        if filter.parents_only.unwrap_or(false) {
            stmt = stmt.filter(outline_keys::parent_id.is_null());
        } else if let Some(parent_id) = filter.parent_id {
            stmt = stmt.filter(outline_keys::parent_id.eq(parent_id));
        }

        stmt.select(OutlineKey::as_select())
            .order(outline_keys::id.asc())
            .load::<OutlineKey>(&mut conn)
            .map_err(anyhow::Error::from)
    })
    .await;

    match query {
        Ok(Ok(rows)) => HttpResponse::Ok().json(
            rows.into_iter()
                .map(OutlineKeyResponse::from)
                .collect::<Vec<_>>(),
        ),
        _ => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to list outline keys".to_string(),
        }),
    }
}

#[utoipa::path(
    get,
    path = "/outline-keys/{id}",
    params(
        ("id" = i32, Path, description = "Outline key id")
    ),
    responses(
        (status = 200, body = OutlineKeyResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "outline-keys"
)]
#[get("/outline-keys/{id}")]
pub async fn get_outline_key(
    auth: AuthUser,
    path: web::Path<i32>,
    pool: web::Data<PgPool>,
) -> impl Responder {
    if !auth.is_admin() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            message: "admin only route".to_string(),
        });
    }

    let key_id = path.into_inner();
    let query_pool = pool.clone();
    let query = web::block(move || {
        let mut conn = query_pool.get()?;
        outline_keys::table
            .filter(outline_keys::id.eq(key_id))
            .select(OutlineKey::as_select())
            .first::<OutlineKey>(&mut conn)
            .optional()
            .map_err(anyhow::Error::from)
    })
    .await;

    match query {
        Ok(Ok(Some(key))) => HttpResponse::Ok().json(OutlineKeyResponse::from(key)),
        Ok(Ok(None)) => HttpResponse::NotFound().json(ErrorResponse {
            message: "outline key not found".to_string(),
        }),
        _ => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to get outline key".to_string(),
        }),
    }
}

#[utoipa::path(
    patch,
    path = "/outline-keys/{id}",
    request_body = UpdateOutlineKeyRequest,
    params(
        ("id" = i32, Path, description = "Outline key id")
    ),
    responses(
        (status = 200, body = OutlineKeyResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "outline-keys"
)]
#[patch("/outline-keys/{id}")]
pub async fn update_outline_key(
    auth: AuthUser,
    path: web::Path<i32>,
    pool: web::Data<PgPool>,
    payload: web::Json<UpdateOutlineKeyRequest>,
) -> impl Responder {
    if !auth.is_admin() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            message: "admin only route".to_string(),
        });
    }

    let key_id = path.into_inner();
    let req = payload.into_inner();
    let query_pool = pool.clone();
    let query = web::block(move || {
        let mut conn = query_pool.get()?;
        let maybe = outline_keys::table
            .filter(outline_keys::id.eq(key_id))
            .select(OutlineKey::as_select())
            .first::<OutlineKey>(&mut conn)
            .optional()
            .map_err(anyhow::Error::from)?;
        let current = match maybe {
            Some(v) => v,
            None => return Ok::<Option<OutlineKey>, anyhow::Error>(None),
        };

        let updated = diesel::update(outline_keys::table.filter(outline_keys::id.eq(key_id)))
            .set((
                outline_keys::name.eq(req.name.or(current.name)),
                outline_keys::outline_key.eq(req.outline_key.or(current.outline_key)),
                outline_keys::country.eq(req.country.or(current.country)),
                outline_keys::parent_id.eq(req.parent_id.or(current.parent_id)),
            ))
            .returning(OutlineKey::as_returning())
            .get_result::<OutlineKey>(&mut conn)
            .map_err(anyhow::Error::from)?;
        Ok::<Option<OutlineKey>, anyhow::Error>(Some(updated))
    })
    .await;

    match query {
        Ok(Ok(Some(key))) => HttpResponse::Ok().json(OutlineKeyResponse::from(key)),
        Ok(Ok(None)) => HttpResponse::NotFound().json(ErrorResponse {
            message: "outline key not found".to_string(),
        }),
        _ => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to update outline key".to_string(),
        }),
    }
}

#[utoipa::path(
    post,
    path = "/users/{id}/assign-parent-key",
    request_body = AssignParentKeyRequest,
    params(
        ("id" = i32, Path, description = "User id")
    ),
    responses(
        (status = 200, body = ErrorResponse),
        (status = 400, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "users"
)]
#[post("/users/{id}/assign-parent-key")]
pub async fn assign_parent_key_to_user(
    auth: AuthUser,
    path: web::Path<i32>,
    pool: web::Data<PgPool>,
    payload: web::Json<AssignParentKeyRequest>,
) -> impl Responder {
    if !auth.is_admin() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            message: "admin only route".to_string(),
        });
    }

    let user_id = path.into_inner();
    let req = payload.into_inner();
    let query_pool = pool.clone();
    let result = web::block(move || {
        let mut conn = query_pool.get()?;

        let exists_user = users::table
            .filter(users::id.eq(user_id))
            .select(users::id)
            .first::<i32>(&mut conn)
            .optional()
            .map_err(anyhow::Error::from)?;
        if exists_user.is_none() {
            return Ok::<&'static str, anyhow::Error>("user_not_found");
        }

        let parent = outline_keys::table
            .filter(outline_keys::id.eq(req.parent_outline_key_id))
            .select(OutlineKey::as_select())
            .first::<OutlineKey>(&mut conn)
            .optional()
            .map_err(anyhow::Error::from)?;
        let parent = match parent {
            Some(v) => v,
            None => return Ok::<&'static str, anyhow::Error>("parent_not_found"),
        };

        if parent.parent_id.is_some() {
            return Ok::<&'static str, anyhow::Error>("not_parent_key");
        }

        let exists_link = user_access_keys::table
            .filter(user_access_keys::user_id.eq(user_id))
            .filter(user_access_keys::outline_key_id.eq(parent.id))
            .select(user_access_keys::id)
            .first::<i32>(&mut conn)
            .optional()
            .map_err(anyhow::Error::from)?;
        if exists_link.is_some() {
            return Ok::<&'static str, anyhow::Error>("already_assigned");
        }

        diesel::insert_into(user_access_keys::table)
            .values((
                user_access_keys::user_id.eq(user_id),
                user_access_keys::outline_key_id.eq(parent.id),
            ))
            .execute(&mut conn)
            .map_err(anyhow::Error::from)?;
        Ok::<&'static str, anyhow::Error>("assigned")
    })
    .await;

    match result {
        Ok(Ok("assigned")) => HttpResponse::Ok().json(ErrorResponse {
            message: "parent key assigned to user".to_string(),
        }),
        Ok(Ok("already_assigned")) => HttpResponse::Ok().json(ErrorResponse {
            message: "parent key already assigned to user".to_string(),
        }),
        Ok(Ok("user_not_found")) => HttpResponse::NotFound().json(ErrorResponse {
            message: "user not found".to_string(),
        }),
        Ok(Ok("parent_not_found")) => HttpResponse::NotFound().json(ErrorResponse {
            message: "parent outline key not found".to_string(),
        }),
        Ok(Ok("not_parent_key")) => HttpResponse::BadRequest().json(ErrorResponse {
            message: "outline key is not a parent key".to_string(),
        }),
        _ => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to assign parent key".to_string(),
        }),
    }
}

#[utoipa::path(
    get,
    path = "/me/outline-keys",
    params(
        ("parent_id" = Option<i32>, Query, description = "Optional parent key id filter")
    ),
    responses(
        (status = 200, body = [OutlineKeyResponse]),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "users"
)]
#[get("/me/outline-keys")]
pub async fn my_outline_keys(
    auth: AuthUser,
    query: web::Query<MyOutlineKeyQuery>,
    pool: web::Data<PgPool>,
) -> impl Responder {
    let filter = query.into_inner();
    let query_pool = pool.clone();
    let user_id = auth.user_id;
    let now = Utc::now().naive_utc();

    let query = web::block(move || {
        let mut conn = query_pool.get()?;

        let user = users::table
            .filter(users::id.eq(user_id))
            .select(User::as_select())
            .first::<User>(&mut conn)
            .optional()
            .map_err(anyhow::Error::from)?;

        let user = match user {
            Some(u) => u,
            None => {
                return Ok::<Result<Vec<OutlineKey>, &'static str>, anyhow::Error>(Err(
                    "user_not_found",
                ));
            }
        };

        if let Some(expired_at) = user.expired_at {
            if expired_at <= now {
                return Ok::<Result<Vec<OutlineKey>, &'static str>, anyhow::Error>(Err(
                    "user_expired",
                ));
            }
        }

        let mut parent_ids_query = user_access_keys::table
            .inner_join(
                outline_keys::table.on(outline_keys::id.eq(user_access_keys::outline_key_id)),
            )
            .filter(user_access_keys::user_id.eq(user_id))
            .filter(outline_keys::parent_id.is_null())
            .select(outline_keys::id)
            .into_boxed();

        if let Some(parent_id) = filter.parent_id {
            parent_ids_query = parent_ids_query.filter(outline_keys::id.eq(parent_id));
        }

        let parent_ids: Vec<i32> = parent_ids_query
            .load::<i32>(&mut conn)
            .map_err(anyhow::Error::from)?;

        if parent_ids.is_empty() {
            return Ok::<Result<Vec<OutlineKey>, &'static str>, anyhow::Error>(Ok(vec![]));
        }

        let child_keys = outline_keys::table
            .filter(outline_keys::parent_id.eq_any(parent_ids))
            .filter(outline_keys::outline_key.is_not_null())
            .select(OutlineKey::as_select())
            .order(outline_keys::id.asc())
            .load::<OutlineKey>(&mut conn)
            .map_err(anyhow::Error::from)?;

        Ok::<Result<Vec<OutlineKey>, &'static str>, anyhow::Error>(Ok(child_keys))
    })
    .await;

    match query {
        Ok(Ok(Ok(keys))) => HttpResponse::Ok().json(
            keys.into_iter()
                .map(OutlineKeyResponse::from)
                .collect::<Vec<_>>(),
        ),
        Ok(Ok(Err("user_expired"))) => HttpResponse::Forbidden().json(ErrorResponse {
            message: "user is expired".to_string(),
        }),
        Ok(Ok(Err("user_not_found"))) => HttpResponse::Unauthorized().json(ErrorResponse {
            message: "user not found".to_string(),
        }),
        _ => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to load outline keys".to_string(),
        }),
    }
}

#[utoipa::path(
    delete,
    path = "/outline-keys/{id}",
    params(
        ("id" = i32, Path, description = "Outline key id")
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "outline-keys"
)]
#[actix_web::delete("/outline-keys/{id}")]
pub async fn delete_outline_key(
    auth: AuthUser,
    path: web::Path<i32>,
    pool: web::Data<PgPool>,
) -> impl Responder {
    if !auth.is_admin() {
        return HttpResponse::Forbidden().json(ErrorResponse {
            message: "admin only route".to_string(),
        });
    }

    let key_id = path.into_inner();
    let query_pool = pool.clone();
    let query = web::block(move || {
        let mut conn = query_pool.get()?;
        diesel::delete(outline_keys::table.filter(outline_keys::id.eq(key_id)))
            .execute(&mut conn)
            .map_err(anyhow::Error::from)
    })
    .await;

    match query {
        Ok(Ok(0)) => HttpResponse::NotFound().json(ErrorResponse {
            message: "outline key not found".to_string(),
        }),
        Ok(Ok(_)) => HttpResponse::NoContent().finish(),
        _ => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to delete outline key".to_string(),
        }),
    }
}

#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, body = TokenPairResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    tag = "auth"
)]
#[post("/auth/login")]
pub async fn login(
    cfg: web::Data<AppConfig>,
    pool: web::Data<PgPool>,
    payload: web::Json<LoginRequest>,
) -> impl Responder {
    let req = payload.into_inner();
    if req.username.trim().is_empty() || req.password.trim().is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            message: "username and password are required".to_string(),
        });
    }

    let query_pool = pool.clone();
    let username = req.username.clone();
    let user_query = web::block(move || {
        let mut conn = query_pool.get()?;
        users::table
            .filter(users::username.eq(username))
            .select(User::as_select())
            .first::<User>(&mut conn)
            .optional()
            .map_err(anyhow::Error::from)
    })
    .await;

    let user = match user_query {
        Ok(Ok(Some(user))) => user,
        Ok(Ok(None)) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                message: "invalid username or password".to_string(),
            });
        }
        _ => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                message: "failed to login".to_string(),
            });
        }
    };

    let valid = match verify_password(&req.password, &user.password_hashed) {
        Ok(v) => v,
        Err(_) => false,
    };
    if !valid {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            message: "invalid username or password".to_string(),
        });
    }

    match generate_token_pair(&cfg, user.id, &user.username, &user.type_) {
        Ok((access_token, new_refresh_token)) => {
            let pool = pool.clone();
            let user_id = user.id;
            let token_to_store = new_refresh_token.clone();
            let save_result = web::block(move || {
                let mut conn = pool.get()?;
                diesel::update(users::table.filter(users::id.eq(user_id)))
                    .set(users::refresh_token.eq(Some(token_to_store)))
                    .execute(&mut conn)
                    .map_err(anyhow::Error::from)
            })
            .await;

            match save_result {
                Ok(Ok(_)) => HttpResponse::Ok().json(TokenPairResponse {
                    access_token,
                    refresh_token: new_refresh_token,
                }),
                _ => HttpResponse::InternalServerError().json(ErrorResponse {
                    message: "failed to persist refresh token".to_string(),
                }),
            }
        }
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to generate tokens".to_string(),
        }),
    }
}

#[utoipa::path(
    post,
    path = "/auth/refresh",
    request_body = RefreshTokenRequest,
    responses(
        (status = 200, body = TokenPairResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    tag = "auth"
)]
#[post("/auth/refresh")]
pub async fn refresh(
    cfg: web::Data<AppConfig>,
    pool: web::Data<PgPool>,
    payload: web::Json<RefreshTokenRequest>,
) -> impl Responder {
    let req = payload.into_inner();
    if req.refresh_token.trim().is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            message: "refresh_token is required".to_string(),
        });
    }

    let claims = match decode_token(&cfg, &req.refresh_token) {
        Ok(claims) => claims,
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                message: "invalid refresh token".to_string(),
            });
        }
    };

    if claims.token_type != "refresh" {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            message: "invalid token type".to_string(),
        });
    }

    let query_pool = pool.clone();
    let user_id = claims.sub;
    let user_query = web::block(move || {
        let mut conn = query_pool.get()?;
        users::table
            .filter(users::id.eq(user_id))
            .select(User::as_select())
            .first::<User>(&mut conn)
            .optional()
            .map_err(anyhow::Error::from)
    })
    .await;

    let user = match user_query {
        Ok(Ok(Some(user))) => user,
        Ok(Ok(None)) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                message: "user not found".to_string(),
            });
        }
        _ => {
            return HttpResponse::InternalServerError().json(ErrorResponse {
                message: "failed to refresh token".to_string(),
            });
        }
    };

    if user.refresh_token.as_deref() != Some(req.refresh_token.as_str()) {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            message: "refresh token mismatch".to_string(),
        });
    }

    match generate_token_pair(&cfg, user.id, &user.username, &user.type_) {
        Ok((access_token, new_refresh_token)) => {
            let pool = pool.clone();
            let user_id = user.id;
            let token_to_store = new_refresh_token.clone();
            let save_result = web::block(move || {
                let mut conn = pool.get()?;
                diesel::update(users::table.filter(users::id.eq(user_id)))
                    .set(users::refresh_token.eq(Some(token_to_store)))
                    .execute(&mut conn)
                    .map_err(anyhow::Error::from)
            })
            .await;

            match save_result {
                Ok(Ok(_)) => HttpResponse::Ok().json(TokenPairResponse {
                    access_token,
                    refresh_token: new_refresh_token,
                }),
                _ => HttpResponse::InternalServerError().json(ErrorResponse {
                    message: "failed to persist refresh token".to_string(),
                }),
            }
        }
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
            message: "failed to generate tokens".to_string(),
        }),
    }
}
