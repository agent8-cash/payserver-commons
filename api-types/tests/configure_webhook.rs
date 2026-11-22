use api_types::store::ConfigureWebhookRequest;
use serde_json::json;

#[test]
fn deserialize_without_rotate_secret() {
    let data = json!({"webhook_url": "https://example.com", "enabled": true});
    let req: ConfigureWebhookRequest = serde_json::from_value(data).unwrap();
    assert!(!req.rotate_secret);
}

#[test]
fn deserialize_with_rotate_secret_true() {
    let data =
        json!({"webhook_url": "https://example.com", "enabled": true, "rotate_secret": true});
    let req: ConfigureWebhookRequest = serde_json::from_value(data).unwrap();
    assert!(req.rotate_secret);
}
