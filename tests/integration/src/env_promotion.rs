use sigyn_core::crypto::keys::KeyFingerprint;
use sigyn_core::environment::promotion::promote_env;
use sigyn_core::secrets::types::SecretValue;
use sigyn_core::vault::env_file::PlaintextEnv;

fn make_fp(byte: u8) -> KeyFingerprint {
    KeyFingerprint([byte; 16])
}

#[test]
fn test_promote_dev_to_staging() {
    let fp = make_fp(1);

    // 1. Create dev env with 5 secrets
    let mut dev = PlaintextEnv::new();
    dev.set(
        "DB_URL".into(),
        SecretValue::String("postgres://dev".into()),
        &fp,
    );
    dev.set(
        "API_KEY".into(),
        SecretValue::String("sk-dev-111".into()),
        &fp,
    );
    dev.set(
        "REDIS_URL".into(),
        SecretValue::String("redis://dev".into()),
        &fp,
    );
    dev.set("LOG_LEVEL".into(), SecretValue::String("debug".into()), &fp);
    dev.set(
        "FEATURE_FLAG".into(),
        SecretValue::String("true".into()),
        &fp,
    );

    // 2. Create staging env with 2 secrets, one overlapping key (API_KEY)
    let mut staging = PlaintextEnv::new();
    staging.set(
        "API_KEY".into(),
        SecretValue::String("sk-staging-old".into()),
        &fp,
    );
    staging.set(
        "CDN_URL".into(),
        SecretValue::String("https://cdn.staging".into()),
        &fp,
    );

    // 3. Promote dev to staging (no filter = all keys)
    let result = promote_env(&dev, &mut staging, &fp, None);

    // 4. Verify all 5 dev secrets are in staging
    assert_eq!(result.promoted_keys.len(), 5);
    assert!(result.promoted_keys.contains(&"DB_URL".to_string()));
    assert!(result.promoted_keys.contains(&"API_KEY".to_string()));
    assert!(result.promoted_keys.contains(&"REDIS_URL".to_string()));
    assert!(result.promoted_keys.contains(&"LOG_LEVEL".to_string()));
    assert!(result.promoted_keys.contains(&"FEATURE_FLAG".to_string()));

    // 5. Verify the overlapping key (API_KEY) was overwritten
    assert_eq!(result.overwritten_keys, vec!["API_KEY".to_string()]);
    assert_eq!(
        staging.get("API_KEY").unwrap().value,
        SecretValue::String("sk-dev-111".into())
    );

    // 6. Staging should have 7 keys total: 5 from dev + 2 original (CDN_URL was not overwritten)
    // Wait: dev has 5 keys, staging had 2, one overlapping = 5 + 2 - 1 = 6
    assert_eq!(staging.len(), 6);

    // CDN_URL should still be there (promotion does not remove existing keys)
    assert_eq!(
        staging.get("CDN_URL").unwrap().value,
        SecretValue::String("https://cdn.staging".into())
    );

    // Verify all dev values are present in staging
    assert_eq!(
        staging.get("DB_URL").unwrap().value,
        SecretValue::String("postgres://dev".into())
    );
    assert_eq!(
        staging.get("REDIS_URL").unwrap().value,
        SecretValue::String("redis://dev".into())
    );
    assert_eq!(
        staging.get("LOG_LEVEL").unwrap().value,
        SecretValue::String("debug".into())
    );
    assert_eq!(
        staging.get("FEATURE_FLAG").unwrap().value,
        SecretValue::String("true".into())
    );
}

#[test]
fn test_filtered_promotion_only_selected_keys() {
    let fp = make_fp(2);

    let mut dev = PlaintextEnv::new();
    dev.set(
        "DB_URL".into(),
        SecretValue::String("postgres://dev".into()),
        &fp,
    );
    dev.set("API_KEY".into(), SecretValue::String("sk-dev".into()), &fp);
    dev.set(
        "SECRET_SAUCE".into(),
        SecretValue::String("spicy".into()),
        &fp,
    );

    let mut staging = PlaintextEnv::new();

    // Only promote DB_URL and API_KEY
    let filter = vec!["DB_URL".to_string(), "API_KEY".to_string()];
    let result = promote_env(&dev, &mut staging, &fp, Some(&filter));

    assert_eq!(result.promoted_keys.len(), 2);
    assert!(result.skipped_keys.is_empty());
    assert!(result.overwritten_keys.is_empty());

    // SECRET_SAUCE should NOT be in staging
    assert!(staging.get("SECRET_SAUCE").is_none());
    assert_eq!(staging.len(), 2);
}

#[test]
fn test_promotion_with_nonexistent_keys_in_filter() {
    let fp = make_fp(3);

    let mut dev = PlaintextEnv::new();
    dev.set(
        "DB_URL".into(),
        SecretValue::String("postgres://dev".into()),
        &fp,
    );

    let mut staging = PlaintextEnv::new();

    let filter = vec![
        "DB_URL".to_string(),
        "NONEXISTENT_1".to_string(),
        "NONEXISTENT_2".to_string(),
    ];
    let result = promote_env(&dev, &mut staging, &fp, Some(&filter));

    assert_eq!(result.promoted_keys, vec!["DB_URL".to_string()]);
    assert_eq!(result.skipped_keys.len(), 2);
    assert!(result.skipped_keys.contains(&"NONEXISTENT_1".to_string()));
    assert!(result.skipped_keys.contains(&"NONEXISTENT_2".to_string()));
}

#[test]
fn test_promote_empty_source_is_noop() {
    let fp = make_fp(4);

    let source = PlaintextEnv::new();
    let mut target = PlaintextEnv::new();
    target.set(
        "EXISTING".into(),
        SecretValue::String("keep-me".into()),
        &fp,
    );

    let result = promote_env(&source, &mut target, &fp, None);

    assert!(result.promoted_keys.is_empty());
    assert!(result.skipped_keys.is_empty());
    assert!(result.overwritten_keys.is_empty());
    assert_eq!(target.len(), 1);
    assert_eq!(
        target.get("EXISTING").unwrap().value,
        SecretValue::String("keep-me".into())
    );
}

#[test]
fn test_promote_all_keys_overwrite() {
    let fp = make_fp(5);

    let mut source = PlaintextEnv::new();
    source.set("A".into(), SecretValue::String("src-a".into()), &fp);
    source.set("B".into(), SecretValue::String("src-b".into()), &fp);

    let mut target = PlaintextEnv::new();
    target.set("A".into(), SecretValue::String("old-a".into()), &fp);
    target.set("B".into(), SecretValue::String("old-b".into()), &fp);

    let result = promote_env(&source, &mut target, &fp, None);

    assert_eq!(result.promoted_keys.len(), 2);
    assert_eq!(result.overwritten_keys.len(), 2);
    assert_eq!(
        target.get("A").unwrap().value,
        SecretValue::String("src-a".into())
    );
    assert_eq!(
        target.get("B").unwrap().value,
        SecretValue::String("src-b".into())
    );
}
