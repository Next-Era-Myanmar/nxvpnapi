// @generated automatically by Diesel CLI.

diesel::table! {
    outline_keys (id) {
        id -> Int4,
        name -> Nullable<Text>,
        outline_key -> Nullable<Text>,
        country -> Nullable<Text>,
        parent_id -> Nullable<Int4>,
    }
}

diesel::table! {
    user_access_keys (id) {
        id -> Int4,
        user_id -> Int4,
        outline_key_id -> Int4,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        display_name -> Nullable<Text>,
        username -> Text,
        password_hashed -> Text,
        contact_email -> Nullable<Text>,
        expired_at -> Nullable<Timestamp>,
        refresh_token -> Nullable<Text>,
        #[sql_name = "type"]
        #[max_length = 10]
        type_ -> Varchar,
        created_at -> Timestamp,
    }
}

diesel::joinable!(user_access_keys -> outline_keys (outline_key_id));
diesel::joinable!(user_access_keys -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    outline_keys,
    user_access_keys,
    users,
);
