diesel::table! {
    surge.identity (id) {
        id -> Uuid,
        username -> Text,
        display_name -> Text,
        avatar_url -> Nullable<Text>,
        state -> Text,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    surge.credential_password (identity_id) {
        identity_id -> Uuid,
        hash -> Text,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    surge.session (id) {
        id -> Uuid,
        token_hash -> Bytea,
        identity_id -> Uuid,
        authenticated_via -> Jsonb,
        issued_at -> Timestamptz,
        expires_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    surge.login_flow (id) {
        id -> Text,
        return_to -> Nullable<Text>,
        csrf_token -> Text,
        state -> Text,
        attempts -> Int4,
        error -> Nullable<Text>,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    surge.invite_code (code_hash) {
        code_hash -> Bytea,
        created_at -> Timestamptz,
        used_by -> Nullable<Uuid>,
        used_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    surge.service (id) {
        id -> Uuid,
        name -> Text,
        token_hash -> Bytea,
        grants -> Array<Text>,
        return_origins -> Array<Text>,
        created_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    surge.audit_log (id) {
        id -> Int8,
        at -> Timestamptz,
        actor -> Jsonb,
        action -> Text,
        subject -> Jsonb,
        detail -> Nullable<Jsonb>,
    }
}

diesel::table! {
    surge.rate_limit_window (key, window_start) {
        key -> Text,
        window_start -> Timestamptz,
        count -> Int4,
    }
}

diesel::joinable!(credential_password -> identity (identity_id));
diesel::joinable!(session -> identity (identity_id));

diesel::allow_tables_to_appear_in_same_query!(identity, credential_password, session,);
