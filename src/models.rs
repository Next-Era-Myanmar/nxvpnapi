use chrono::NaiveDateTime;
use diesel::{Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::schema::{outline_keys, user_access_keys, users};

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = users)]
pub struct User {
    pub id: i32,
    pub display_name: Option<String>,
    pub username: String,
    pub password_hashed: String,
    pub contact_email: Option<String>,
    pub expired_at: Option<NaiveDateTime>,
    pub refresh_token: Option<String>,
    pub type_: String,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub display_name: Option<String>,
    pub username: String,
    pub password: String,
    pub contact_email: Option<String>,
    pub expired_at: Option<NaiveDateTime>,
    #[serde(rename = "type")]
    pub type_: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub display_name: Option<String>,
    pub contact_email: Option<String>,
    pub expired_at: Option<NaiveDateTime>,
    #[serde(rename = "type")]
    pub type_: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ResetPasswordRequest {
    pub new_password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangeMyPasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOutlineKeyRequest {
    pub name: String,
    pub outline_key: Option<String>,
    pub country: Option<String>,
    pub parent_id: Option<i32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateOutlineKeyRequest {
    pub name: Option<String>,
    pub outline_key: Option<String>,
    pub country: Option<String>,
    pub parent_id: Option<i32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignParentKeyRequest {
    pub parent_outline_key_id: i32,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct OutlineKeyFilterQuery {
    pub parent_id: Option<i32>,
    pub parents_only: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MyOutlineKeyQuery {
    pub parent_id: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenPairResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub display_name: Option<String>,
    pub username: String,
    pub password_hashed: String,
    pub contact_email: Option<String>,
    pub expired_at: Option<NaiveDateTime>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: i32,
    pub display_name: Option<String>,
    pub username: String,
    pub contact_email: Option<String>,
    pub expired_at: Option<NaiveDateTime>,
    pub type_: String,
    pub created_at: NaiveDateTime,
}

impl From<User> for UserResponse {
    fn from(value: User) -> Self {
        Self {
            id: value.id,
            display_name: value.display_name,
            username: value.username,
            contact_email: value.contact_email,
            expired_at: value.expired_at,
            type_: value.type_,
            created_at: value.created_at,
        }
    }
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = outline_keys)]
pub struct OutlineKey {
    pub id: i32,
    pub name: Option<String>,
    pub outline_key: Option<String>,
    pub country: Option<String>,
    pub parent_id: Option<i32>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = outline_keys)]
pub struct NewOutlineKey {
    pub name: String,
    pub outline_key: Option<String>,
    pub country: Option<String>,
    pub parent_id: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OutlineKeyResponse {
    pub id: i32,
    pub name: Option<String>,
    pub outline_key: Option<String>,
    pub country: Option<String>,
    pub parent_id: Option<i32>,
}

impl From<OutlineKey> for OutlineKeyResponse {
    fn from(value: OutlineKey) -> Self {
        Self {
            id: value.id,
            name: value.name,
            outline_key: value.outline_key,
            country: value.country,
            parent_id: value.parent_id,
        }
    }
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = user_access_keys)]
pub struct UserAccessKey {
    pub id: i32,
    pub user_id: i32,
    pub outline_key_id: i32,
}
