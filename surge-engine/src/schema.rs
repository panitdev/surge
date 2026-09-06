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
    surge.credential_totp (identity_id) {
        identity_id -> Uuid,
        secret_encrypted -> Text,
        confirmed_at -> Nullable<Timestamptz>,
        last_used_step -> Nullable<Int8>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    surge.credential_passphrase (identity_id) {
        identity_id -> Uuid,
        hash -> Text,
        updated_at -> Timestamptz,
        confirmed_at -> Nullable<Timestamptz>,
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
        identity_id -> Nullable<Uuid>,
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
    surge.identity_link (provider, subject) {
        provider -> Text,
        subject -> Text,
        identity_id -> Uuid,
        verified_at -> Nullable<Timestamptz>,
        linked_at -> Timestamptz,
    }
}

diesel::table! {
    surge.rate_limit_window (key, window_start) {
        key -> Text,
        window_start -> Timestamptz,
        count -> Int4,
    }
}

diesel::table! {
    surge.oauth_client (client_id) {
        client_id -> Text,
        client_secret_hash -> Nullable<Bytea>,
        client_name -> Text,
        client_uri -> Nullable<Text>,
        logo_uri -> Nullable<Text>,
        redirect_uris -> Array<Text>,
        grant_types -> Array<Text>,
        scopes -> Array<Text>,
        token_endpoint_auth_method -> Text,
        registration_source -> Text,
        first_party -> Bool,
        trust_state -> Text,
        created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    surge.oauth_resource (resource_uri) {
        resource_uri -> Text,
        service_id -> Uuid,
        scopes -> Array<Text>,
        scope_descriptions -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    surge.oauth_consent (client_id, identity_id, resource_uri) {
        client_id -> Text,
        identity_id -> Uuid,
        resource_uri -> Text,
        scopes -> Array<Text>,
        granted_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    surge.oauth_consent_flow (id) {
        id -> Text,
        client_id -> Text,
        identity_id -> Uuid,
        session_id -> Uuid,
        resource_uri -> Text,
        scopes -> Array<Text>,
        redirect_uri -> Text,
        state -> Nullable<Text>,
        nonce -> Nullable<Text>,
        code_challenge -> Text,
        code_challenge_method -> Text,
        csrf_token -> Text,
        decided_at -> Nullable<Timestamptz>,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    surge.oauth_authorization_code (code_hash) {
        code_hash -> Bytea,
        client_id -> Text,
        identity_id -> Uuid,
        session_id -> Uuid,
        resource_uri -> Text,
        redirect_uri -> Text,
        scopes -> Array<Text>,
        code_challenge -> Text,
        code_challenge_method -> Text,
        nonce -> Nullable<Text>,
        issued_at -> Timestamptz,
        expires_at -> Timestamptz,
        consumed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    surge.oauth_refresh_token (token_hash) {
        token_hash -> Bytea,
        client_id -> Text,
        identity_id -> Uuid,
        session_id -> Uuid,
        resource_uri -> Text,
        scopes -> Array<Text>,
        family_id -> Uuid,
        parent_hash -> Nullable<Bytea>,
        issued_at -> Timestamptz,
        expires_at -> Timestamptz,
        consumed_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    surge.oauth_signing_key (kid) {
        kid -> Text,
        algorithm -> Text,
        private_key_encrypted -> Text,
        public_jwk -> Jsonb,
        created_at -> Timestamptz,
        activated_at -> Nullable<Timestamptz>,
        retired_at -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(credential_password -> identity (identity_id));
diesel::joinable!(credential_totp -> identity (identity_id));
diesel::joinable!(credential_passphrase -> identity (identity_id));
diesel::joinable!(identity_link -> identity (identity_id));
diesel::joinable!(session -> identity (identity_id));
diesel::joinable!(oauth_resource -> service (service_id));
diesel::joinable!(oauth_consent -> identity (identity_id));
diesel::joinable!(oauth_consent -> oauth_client (client_id));

diesel::allow_tables_to_appear_in_same_query!(
    identity,
    credential_password,
    credential_totp,
    credential_passphrase,
    identity_link,
    session,
    service,
    oauth_client,
    oauth_resource,
    oauth_consent,
    oauth_consent_flow,
    oauth_authorization_code,
    oauth_refresh_token,
);
