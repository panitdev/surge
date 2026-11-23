//! The one rule deciding whether a client may be issued tokens for a
//! resource registration.
//!
//! It is evaluated against *current* state at every point a token can come
//! into being: authorization, consent completion, code redemption and
//! refresh. A grant that was eligible when it was approved is not eligible
//! for ever — a client's audience list or a resource's allowlist can change
//! in between — so no stage may rely on an earlier stage having checked.
//!
//! The rule, in order:
//!
//! 1. A client-ID-metadata-document (CIMD) client may use a resource only
//!    if its exact client ID URL is in the resource's allowlist.
//! 2. A client with an explicit audience list (`Some`) is restricted to it,
//!    for every resource. An empty list grants nothing. Membership is by
//!    registration, so an approval does not survive the resource being
//!    deleted and registered again.
//! 3. A client with no list (`None`, the legacy default) keeps its existing
//!    access to *service* resources, and has none to delegated resources
//!    unless a dynamically registered client meets a resource that has opted
//!    in to DCR.
//!
//! One further condition applies to dynamically registered clients, because
//! their registration is unauthenticated: an explicit binding to a delegated
//! resource is honoured only if that resource has opted in to DCR. Otherwise
//! anyone could bind themselves to any developer's resource.

use super::{OauthClient, OauthResource, RegistrationSource, ResourceSource};

/// True when `client` may be issued tokens for `resource`.
pub fn client_may_use_resource(client: &OauthClient, resource: &OauthResource) -> bool {
    let delegated = resource.registration_source == ResourceSource::Delegated;
    // Only `Dynamic` gets DCR opt-in admission. A `Platform` client is bound
    // by its registrar to specific registrations and relies on that explicit
    // list alone: it is never admitted through the no-list branch.
    let dynamic = client.registration_source == RegistrationSource::Dynamic;

    // First, so a CIMD client is always held to the allowlist whatever else
    // is stored for it.
    if is_cimd_client_id(&client.client_id) {
        return resource.allowed_cimd_client_ids.contains(&client.client_id);
    }

    if let Some(approved) = &client.audiences {
        if !approved.contains(&resource.resource_uri) {
            return false;
        }
        return !(delegated && dynamic && !resource.dcr_enabled);
    }

    if !delegated {
        return true;
    }
    dynamic && resource.dcr_enabled
}

/// A CIMD client's identifier is the HTTPS URL of its metadata document;
/// every client registered here gets a generated `aeg_cid_…` identifier, so
/// the two cannot be confused.
fn is_cimd_client_id(client_id: &str) -> bool {
    client_id.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn client(source: RegistrationSource, audiences: Option<Vec<&str>>) -> OauthClient {
        client_id("aeg_cid_x", source, audiences)
    }

    fn client_id(
        id: &str,
        source: RegistrationSource,
        audiences: Option<Vec<&str>>,
    ) -> OauthClient {
        OauthClient {
            client_id: id.into(),
            client_name: "c".into(),
            client_uri: None,
            logo_uri: None,
            redirect_uris: vec![],
            grant_types: vec![],
            scopes: vec![],
            token_endpoint_auth_method: "none".into(),
            registration_source: source,
            first_party: false,
            trust_state: "untrusted".into(),
            confidential: false,
            audiences: audiences.map(|a| a.into_iter().map(String::from).collect()),
            registrar_service_id: None,
            created_at: Utc::now(),
        }
    }

    fn resource(source: ResourceSource, dcr: bool, cimd: Vec<&str>) -> OauthResource {
        OauthResource {
            registration_id: Uuid::now_v7(),
            resource_uri: "https://rs.example/mcp".into(),
            registration_source: source,
            service_id: None,
            registrar_service_id: None,
            scopes: vec![],
            scope_descriptions: serde_json::json!({}),
            allowed_cimd_client_ids: cimd.into_iter().map(String::from).collect(),
            dcr_enabled: dcr,
            created_at: Utc::now(),
        }
    }

    const URI: &str = "https://rs.example/mcp";

    #[test]
    fn an_empty_list_grants_nothing() {
        let c = client(RegistrationSource::Admin, Some(vec![]));
        assert!(!client_may_use_resource(
            &c,
            &resource(ResourceSource::Service, false, vec![])
        ));
        assert!(!client_may_use_resource(
            &c,
            &resource(ResourceSource::Delegated, true, vec![])
        ));
    }

    #[test]
    fn an_explicit_list_restricts_service_resources_too() {
        let other = client(
            RegistrationSource::Admin,
            Some(vec!["https://other.example/mcp"]),
        );
        let listed = client(RegistrationSource::Admin, Some(vec![URI]));
        let r = resource(ResourceSource::Service, false, vec![]);
        assert!(!client_may_use_resource(&other, &r));
        assert!(client_may_use_resource(&listed, &r));
    }

    #[test]
    fn null_keeps_service_access_and_not_delegated() {
        let c = client(RegistrationSource::Admin, None);
        assert!(client_may_use_resource(
            &c,
            &resource(ResourceSource::Service, false, vec![])
        ));
        assert!(!client_may_use_resource(
            &c,
            &resource(ResourceSource::Delegated, false, vec![])
        ));
        // DCR opt-in is for dynamic clients only.
        assert!(!client_may_use_resource(
            &c,
            &resource(ResourceSource::Delegated, true, vec![])
        ));
    }

    #[test]
    fn a_binding_grants_delegated_access_to_an_admin_client() {
        let c = client(RegistrationSource::Admin, Some(vec![URI]));
        assert!(client_may_use_resource(
            &c,
            &resource(ResourceSource::Delegated, false, vec![])
        ));
    }

    #[test]
    fn a_dynamic_client_needs_the_dcr_opt_in_for_delegated_resources() {
        let unbound = client(RegistrationSource::Dynamic, None);
        let bound = client(RegistrationSource::Dynamic, Some(vec![URI]));
        let closed = resource(ResourceSource::Delegated, false, vec![]);
        let open = resource(ResourceSource::Delegated, true, vec![]);
        assert!(!client_may_use_resource(&unbound, &closed));
        assert!(client_may_use_resource(&unbound, &open));
        assert!(!client_may_use_resource(&bound, &closed));
        assert!(client_may_use_resource(&bound, &open));
        // The opt-in changes nothing for service resources.
        let service = resource(ResourceSource::Service, false, vec![]);
        assert!(client_may_use_resource(&unbound, &service));
    }

    #[test]
    fn a_cimd_client_needs_an_exact_allowlist_entry() {
        let id = "https://app.example/client.json";
        let c = client_id(id, RegistrationSource::Dynamic, None);
        for source in [ResourceSource::Service, ResourceSource::Delegated] {
            assert!(!client_may_use_resource(
                &c,
                &resource(source, true, vec![])
            ));
            assert!(!client_may_use_resource(
                &c,
                &resource(source, true, vec!["https://app.example/client.json/"])
            ));
            assert!(client_may_use_resource(
                &c,
                &resource(source, false, vec![id])
            ));
        }
    }
}
