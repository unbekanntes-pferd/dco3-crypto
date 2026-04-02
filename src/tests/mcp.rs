use schemars::schema_for;
use serde_json::Value;

fn schema_json<T: schemars::JsonSchema>() -> Value {
    serde_json::to_value(schema_for!(T)).unwrap()
}

#[test]
fn public_key_container_schema_uses_serde_field_names() {
    let schema = schema_json::<crate::PublicKeyContainer>();
    let properties = schema["properties"].as_object().unwrap();
    let required = schema["required"].as_array().unwrap();

    assert!(properties.contains_key("publicKey"));
    assert!(properties.contains_key("createdAt"));
    assert!(properties.contains_key("expireAt"));
    assert!(properties.contains_key("createdBy"));
    assert!(required.contains(&Value::String("version".to_string())));
    assert!(required.contains(&Value::String("publicKey".to_string())));
    assert!(!required.contains(&Value::String("createdAt".to_string())));
}

#[test]
fn user_key_pair_container_schema_contains_nested_defs() {
    let schema = schema_json::<crate::UserKeyPairContainer>();
    let defs = schema["$defs"].as_object().unwrap();

    assert!(defs.contains_key("PrivateKeyContainer"));
    assert!(defs.contains_key("PublicKeyContainer"));
    assert!(schema["properties"]
        .as_object()
        .unwrap()
        .contains_key("privateKeyContainer"));
    assert!(schema["properties"]
        .as_object()
        .unwrap()
        .contains_key("publicKeyContainer"));
}

#[test]
fn plain_file_key_schema_contains_optional_tag() {
    let schema = schema_json::<crate::PlainFileKey>();
    let properties = schema["properties"].as_object().unwrap();
    let required = schema["required"].as_array().unwrap();

    assert!(properties.contains_key("key"));
    assert!(properties.contains_key("iv"));
    assert!(properties.contains_key("version"));
    assert!(properties.contains_key("tag"));
    assert!(!required.contains(&Value::String("tag".to_string())));
}
