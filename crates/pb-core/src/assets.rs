//! Static API payloads that the oracle serves verbatim.
//!
//! Both files were recorded from the reference binary
//! (v0.40.6, commit 9d281cca):
//!
//! * `collection_scaffolds.json` — `GET /api/collections/meta/scaffolds`
//! * `oauth2_providers.json` — `GET /api/collections/meta/oauth2-providers`
//!
//! They contain no per-install secrets. The scaffold template is the one
//! exception to "verbatim": `apis/collection.go` builds it with a fresh
//! `security.RandomStringWithAlphabet(10, core.DefaultIdAlphabet)` on every
//! request and uses that id in the default index names, so the recorded suffix
//! is stored as `{{RANDOM_ID}}` and substituted at serve time.

use crate::ids;

/// `GET /api/collections/meta/scaffolds`
const COLLECTION_SCAFFOLDS_TEMPLATE: &str =
    include_str!("../assets/collection_scaffolds.json");

/// `GET /api/collections/meta/oauth2-providers`
pub const OAUTH2_PROVIDERS: &str = include_str!("../assets/oauth2_providers.json");

/// `setDefaultAuthOptions()`: the default auth collection options, recorded from
/// `core.NewAuthCollection` on the oracle. The token `secret` values are absent
/// on purpose — they are per-collection random strings and are generated when a
/// collection is created.
pub const AUTH_OPTIONS_TEMPLATE: &str = include_str!("../assets/auth_options.json");

/// `collectionScaffolds`: the scaffold payload for this request.
pub fn collection_scaffolds() -> String {
    let random_id = ids::random_string_with_alphabet(10, ids::ID_ALPHABET);
    COLLECTION_SCAFFOLDS_TEMPLATE.replace("{{RANDOM_ID}}", &random_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn scaffolds_have_the_three_collection_types() {
        let value: Value = serde_json::from_str(&collection_scaffolds()).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(
            obj.keys().cloned().collect::<Vec<_>>(),
            vec!["base", "auth", "view"]
        );
        assert_eq!(value["auth"]["type"], "auth");
        assert_eq!(value["base"]["system"], false);
        // The scaffold is a template: no id, name or timestamps.
        assert_eq!(value["auth"]["id"], "");
        assert_eq!(value["auth"]["name"], "");
    }

    #[test]
    fn scaffolds_never_carry_token_secrets() {
        let value: Value = serde_json::from_str(&collection_scaffolds()).unwrap();
        for key in [
            "authToken",
            "passwordResetToken",
            "emailChangeToken",
            "verificationToken",
            "fileToken",
        ] {
            assert!(
                value["auth"][key].get("secret").is_none(),
                "{key} must not ship a secret"
            );
            assert!(value["auth"][key].get("duration").is_some());
        }
    }

    #[test]
    fn scaffold_index_names_use_a_fresh_ten_char_id() {
        let first: Value = serde_json::from_str(&collection_scaffolds()).unwrap();
        let second: Value = serde_json::from_str(&collection_scaffolds()).unwrap();
        assert_ne!(first["auth"]["indexes"], second["auth"]["indexes"]);

        for index in first["auth"]["indexes"].as_array().unwrap() {
            let sql = index.as_str().unwrap();
            // `idx_tokenKey_<id>` / `idx_email_<id>` with the empty table name.
            let suffix = sql
                .split("_")
                .last()
                .unwrap()
                .split('`')
                .next()
                .unwrap();
            assert_eq!(suffix.len(), 10, "unexpected index name: {sql}");
            assert!(suffix
                .chars()
                .all(|c| ids::ID_ALPHABET.contains(c)));
            assert!(sql.contains("ON ``"), "not a scaffold index: {sql}");
        }
    }

    #[test]
    fn providers_are_the_full_known_list() {
        let value: Value = serde_json::from_str(OAUTH2_PROVIDERS).unwrap();
        let providers = value.as_array().unwrap();
        assert_eq!(providers.len(), 32);
        assert_eq!(providers[0]["name"], "apple");
        for provider in providers {
            assert!(provider["name"].is_string());
            assert!(provider["displayName"].is_string());
            assert!(provider["logo"].is_string());
        }
    }
}
