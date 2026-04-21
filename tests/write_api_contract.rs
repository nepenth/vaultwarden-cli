use serde_json::json;
use vaultwarden_cli::api::ApiClient;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cipher_response_json() -> serde_json::Value {
    json!({
        "id": "cipher-1",
        "type": 1,
        "name": "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "organizationId": null,
        "collectionIds": []
    })
}

#[tokio::test]
async fn create_cipher_uses_expected_route_and_auth() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/ciphers"))
        .and(header("authorization", "Bearer test-token"))
        .and(body_partial_json(json!({
            "type": 1,
            "name": "enc-name"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(cipher_response_json()))
        .mount(&server)
        .await;

    let api = ApiClient::new(&server.uri()).expect("client");
    let cipher = api
        .create_cipher(
            "test-token",
            &json!({
                "type": 1,
                "name": "enc-name",
                "login": {"username": "enc-user"}
            }),
        )
        .await
        .expect("create should succeed");

    assert_eq!(cipher.id, "cipher-1");
}

#[tokio::test]
async fn update_cipher_uses_expected_route_and_auth() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/api/ciphers/cipher-1"))
        .and(header("authorization", "Bearer test-token"))
        .and(body_partial_json(json!({
            "lastKnownRevisionDate": "2026-04-21T00:00:00.000000Z"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(cipher_response_json()))
        .mount(&server)
        .await;

    let api = ApiClient::new(&server.uri()).expect("client");
    let cipher = api
        .update_cipher(
            "test-token",
            "cipher-1",
            &json!({
                "type": 1,
                "name": "enc-name",
                "lastKnownRevisionDate": "2026-04-21T00:00:00.000000Z"
            }),
        )
        .await
        .expect("update should succeed");

    assert_eq!(cipher.id, "cipher-1");
}

#[tokio::test]
async fn partial_update_uses_partial_route() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/api/ciphers/cipher-1/partial"))
        .and(header("authorization", "Bearer test-token"))
        .and(body_partial_json(json!({
            "folderId": "folder-1",
            "favorite": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(cipher_response_json()))
        .mount(&server)
        .await;

    let api = ApiClient::new(&server.uri()).expect("client");
    let cipher = api
        .update_cipher_partial("test-token", "cipher-1", Some("folder-1"), true)
        .await
        .expect("partial should succeed");

    assert_eq!(cipher.id, "cipher-1");
}

#[tokio::test]
async fn delete_cipher_uses_expected_route_and_auth() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/api/ciphers/cipher-1"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let api = ApiClient::new(&server.uri()).expect("client");
    api.delete_cipher("test-token", "cipher-1")
        .await
        .expect("delete should succeed");
}
