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
//! 0. The global DCR switch is a kill switch: with it off, a dynamically
//!    registered client is ineligible for every resource (after rule 1, which
//!    governs CIMD clients).
//!
//! One further condition applies to dynamically registered clients, because
//! their registration is unauthenticated: an explicit binding to a delegated
//! resource is honoured only if that resource has opted in to DCR. Otherwise
//! anyone could bind themselves to any developer's resource.

/// Deployment-wide inputs to the eligibility rule, kept apart from the rule
/// so it stays a pure function of its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EligibilityPolicy {
    /// The global DCR switch (`SURGE_OAUTH_ALLOW_DYNAMIC_REGISTRATION`). It is
    /// a kill switch: when `false`, a dynamically registered client may use
    /// nothing, so its grants end at their next refresh.
    pub dynamic_clients_enabled: bool,
}

use super::{OauthClient, OauthResource, RegistrationSource, ResourceSource};

/// True when `client` may be issued tokens for `resource`.
pub fn client_may_use_resource(
    client: &OauthClient,
    resource: &OauthResource,
    policy: EligibilityPolicy,
) -> bool {
    // A source this build does not recognise grants nothing to anyone.
    if resource.registration_source == ResourceSource::Unknown
        || client.registration_source == RegistrationSource::Unknown
    {
        return false;
    }
    let delegated = resource.registration_source == ResourceSource::Delegated;
    // Only `Dynamic` gets DCR opt-in admission. A `Platform` client is bound
    // by its registrar to specific registrations and relies on that explicit
    // list alone: it is never admitted through the no-list branch.
    let dynamic = client.registration_source == RegistrationSource::Dynamic;

    // First, so a CIMD client is always held to the allowlist whatever else
    // is stored for it. The `https://` check is belt and braces: the
    // database ties that prefix to the `cimd` source.
    if client.registration_source == RegistrationSource::Cimd
        || is_cimd_client_id(&client.client_id)
    {
        return resource.allowed_cimd_client_ids.contains(&client.client_id);
    }

    // The global kill switch. After the CIMD rule: a CIMD client is not a
    // dynamically registered one, whatever source it is stored with.
    if dynamic && !policy.dynamic_clients_enabled {
        return false;
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

/// The scopes `client` may be granted at `resource`: the resource's *current*
/// scopes, narrowed by the client's own list unless that list is only a
/// snapshot of defaults.
///
/// - an explicit ceiling (`scope_ceiling_explicit`, which is also what every
///   scope list of unknown provenance is treated as) yields
///   `client.scopes ∩ resource.scopes`, so a scope added to a resource later
///   never widens a client that registered for fewer;
/// - a client that registered without naming scopes yields every scope the
///   resource currently offers.
///
/// This decides scope only; eligibility is [`client_may_use_resource`]. The
/// order is the resource's.
pub fn permitted_scopes(client: &OauthClient, resource: &OauthResource) -> Vec<String> {
    resource
        .scopes
        .iter()
        .filter(|s| !client.scope_ceiling_explicit || client.scopes.iter().any(|c| c == *s))
        .cloned()
        .collect()
}

/// True when `resource`'s scopes may be offered to anonymous dynamic client
/// registration as defaults or as a cap: service resources always, delegated
/// ones only after explicitly opting in, and a source this build does not
/// recognise never. Scope names of any other resource must not be revealed
/// to an unauthenticated caller.
pub fn offers_scopes_to_dcr(resource: &OauthResource) -> bool {
    match resource.registration_source {
        ResourceSource::Service => true,
        ResourceSource::Delegated => resource.dcr_enabled,
        ResourceSource::Unknown => false,
    }
}

/// A CIMD client's identifier is the HTTPS URL of its metadata document;
/// every other client gets a generated `aeg_cid_…` identifier, so the two
/// cannot be confused.
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
            scope_ceiling_explicit: true,
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

    const ON: EligibilityPolicy = EligibilityPolicy {
        dynamic_clients_enabled: true,
    };

    /// The rule with the global switch on, which every test but the kill
    /// switch's own assumes.
    fn client_may_use_resource(client: &OauthClient, resource: &OauthResource) -> bool {
        super::client_may_use_resource(client, resource, ON)
    }

    #[test]
    fn the_global_switch_is_a_kill_switch_for_dynamic_clients_only() {
        let off = EligibilityPolicy {
            dynamic_clients_enabled: false,
        };
        let service = resource(ResourceSource::Service, false, vec![]);
        let open = resource(ResourceSource::Delegated, true, vec![]);
        for audiences in [None, Some(vec![URI])] {
            let dynamic = client(RegistrationSource::Dynamic, audiences.clone());
            assert!(super::client_may_use_resource(&dynamic, &service, ON) || audiences.is_some());
            assert!(!super::client_may_use_resource(&dynamic, &service, off));
            assert!(!super::client_may_use_resource(&dynamic, &open, off));
        }
        // Other sources, and CIMD clients, are untouched.
        let admin = client(RegistrationSource::Admin, None);
        assert!(super::client_may_use_resource(&admin, &service, off));
        let cimd = client_id("https://app.example/c.json", RegistrationSource::Dynamic, None);
        let listed = resource(ResourceSource::Service, false, vec!["https://app.example/c.json"]);
        assert!(super::client_may_use_resource(&cimd, &listed, off));
    }

    #[test]
    fn an_unrecognised_source_grants_nothing() {
        let resource = resource(ResourceSource::Unknown, true, vec![]);
        assert!(!client_may_use_resource(
            &client(RegistrationSource::Admin, None),
            &resource
        ));
        let service = self::resource(ResourceSource::Service, false, vec![]);
        assert!(!client_may_use_resource(
            &client(RegistrationSource::Unknown, None),
            &service
        ));
        assert!(!client_may_use_resource(
            &client(RegistrationSource::Unknown, Some(vec![URI])),
            &service
        ));
    }

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
    fn an_explicit_ceiling_is_intersected_with_current_resource_scopes() {
        let mut r = resource(ResourceSource::Delegated, true, vec![]);
        r.scopes = vec!["read".into(), "write".into()];
        let mut c = client(RegistrationSource::Dynamic, None);
        c.scopes = vec!["read".into(), "gone".into()];
        // `write` was added to the resource after registration: no widening.
        assert_eq!(permitted_scopes(&c, &r), vec!["read".to_string()]);
    }

    #[test]
    fn an_omitted_ceiling_follows_the_resource() {
        let mut r = resource(ResourceSource::Delegated, true, vec![]);
        r.scopes = vec!["read".into(), "write".into()];
        let mut c = client(RegistrationSource::Dynamic, None);
        c.scopes = vec!["read".into()];
        c.scope_ceiling_explicit = false;
        assert_eq!(
            permitted_scopes(&c, &r),
            vec!["read".to_string(), "write".to_string()]
        );
    }

    #[test]
    fn only_service_and_opted_in_resources_offer_scopes_to_dcr() {
        assert!(offers_scopes_to_dcr(&resource(ResourceSource::Service, false, vec![])));
        assert!(offers_scopes_to_dcr(&resource(ResourceSource::Delegated, true, vec![])));
        assert!(!offers_scopes_to_dcr(&resource(ResourceSource::Delegated, false, vec![])));
        assert!(!offers_scopes_to_dcr(&resource(ResourceSource::Unknown, true, vec![])));
    }

    #[test]
    fn a_cimd_client_needs_an_exact_allowlist_entry() {
        let id = "https://app.example/client.json";
        // A stored `cimd` row, and an `https://` ID under any other source
        // (which the database forbids) alike: held to the allowlist.
        for kind in [RegistrationSource::Cimd, RegistrationSource::Dynamic] {
            let c = client_id(id, kind, None);
            for source in [ResourceSource::Service, ResourceSource::Delegated] {
                assert!(!client_may_use_resource(&c, &resource(source, true, vec![])));
                assert!(!client_may_use_resource(
                    &c,
                    &resource(source, true, vec!["https://app.example/client.json/"])
                ));
                assert!(client_may_use_resource(&c, &resource(source, false, vec![id])));
            }
        }
    }
}
