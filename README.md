# nxvpnapi

Baseline API frame referenced from `/Users/nyan/workspace/nxera/iam` with:

- `actix-web` for HTTP server
- `scalar_api_reference` for API documentation UI
- `diesel` + PostgreSQL for ORM and migrations

## Structure

- `src/main.rs` app boot, Scalar routes, OpenAPI JSON route
- `src/config.rs` env-based app config
- `src/db.rs` Diesel connection pool
- `src/schema.rs` Diesel schema
- `src/models.rs` request/response and Diesel models
- `src/handlers.rs` sample endpoints (`/health`, `/users`)
- `src/openapi.rs` utoipa OpenAPI document
- `migrations/` Diesel SQL migrations

## Setup

1. Copy env file:
   - `cp .env.example .env`
2. Update `.env` with your PostgreSQL connection string.
3. Create database `nxvpn` and run migrations:
   - `diesel migration run`
4. Start server:
   - `cargo run`

## Docs

- OpenAPI JSON: `http://127.0.0.1:8080/openapi.json`
- Scalar UI: `http://127.0.0.1:8080/scalar`
- Admin Panel: `http://127.0.0.1:8080/admin`

## Auth routes

- `POST /auth/login`
  - body: `{"username":"nxadmin","password":"@dmin123"}`
  - success: `{"access_token":"...","refresh_token":"..."}`
- `POST /auth/refresh`
  - body: `{"refresh_token":"..."}`
  - success: `{"access_token":"...","refresh_token":"..."}`

JWT claims include: `sub`, `username`, `role` (`admin` / `user`), `token_type`, `iat`, `exp`.
Refresh token is persisted in `users.refresh_token`; refresh is allowed only when the provided token matches DB value.

## Authorization rules

- Admin only:
  - `GET /users`
  - `POST /users`
  - `PATCH /users/{id}`
  - `POST /users/{id}/reset-password`
  - `POST /outline-keys`
  - `GET /outline-keys`
    - query: `?parent_id=<id>` or `?parents_only=true`
  - `GET /outline-keys/{id}`
  - `PATCH /outline-keys/{id}`
  - `DELETE /outline-keys/{id}`
  - `POST /users/{id}/assign-parent-key`
- Authenticated user:
  - `GET /me`
  - `POST /me/change-password`
  - `GET /me/outline-keys`
    - returns only child keys under user's assigned parent keys
    - optional query: `?parent_id=<assigned_parent_id>`
    - blocked when user `expired_at` is reached

## Database tables

- `users`
  - `id`, `display_name`, `username`, `password_hashed`, `contact_email`, `expired_at`, `type`, `created_at`
- `outline_keys`
  - `id`, `name`, `outline_key`, `country`, `parent_id`
- `user_access_keys`
  - `id`, `access_key` -> `outline_keys.id`

## Seeded admin user

- `username`: `nxadmin`
- `password`: `@dmin123` (stored as Argon2 hash)
- `contact_email`: `nexteramm@gmail.com`
