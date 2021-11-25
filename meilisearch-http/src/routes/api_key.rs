use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use log::debug;
use meilisearch_lib::index_controller::{Action, Key};
use meilisearch_lib::MeiliSearch;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::analytics::Analytics;
use crate::error::ResponseError;
use crate::extractors::authentication::{policies::*, GuardedData};
use crate::ApiKeys;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            .route(web::post().to(create_api_key))
            .route(web::get().to(list_api_keys)),
    )
    .service(
        web::resource("/{api_key}")
            .route(web::get().to(get_api_key))
            .route(web::patch().to(patch_api_key))
            .route(web::delete().to(delete_api_key)),
    );
}

pub async fn create_api_key(
    meilisearch: GuardedData<Private, MeiliSearch>,
    body: web::Json<Value>,
    _req: HttpRequest,
    analytics: web::Data<dyn Analytics>,
) -> Result<HttpResponse, ResponseError> {
    let key = meilisearch.create_key(body.into_inner()).await?;
    let res = KeyView::from_key(key, meilisearch.master_key());

    debug!("returns: {:?}", res);
    Ok(HttpResponse::Created().json(res))
}

pub async fn list_api_keys(
    meilisearch: GuardedData<Private, MeiliSearch>,
    _req: HttpRequest,
    analytics: web::Data<dyn Analytics>,
) -> Result<HttpResponse, ResponseError> {
    let keys = meilisearch.list_keys().await?;
    let res: Vec<_> = keys
        .into_iter()
        .map(|k| KeyView::from_key(k, meilisearch.master_key()))
        .collect();

    debug!("returns: {:?}", res);
    Ok(HttpResponse::Ok().json(res))
}

pub async fn get_api_key(
    meilisearch: GuardedData<Private, MeiliSearch>,
    path: web::Path<AuthParam>,
    analytics: web::Data<dyn Analytics>,
) -> Result<HttpResponse, ResponseError> {
    // keep 8 first characters that are the ID of the API key.
    let key = meilisearch.get_key(&path.api_key[..8]).await?;
    let res = KeyView::from_key(key, meilisearch.master_key());

    debug!("returns: {:?}", res);
    Ok(HttpResponse::Ok().json(res))
}

pub async fn patch_api_key(
    meilisearch: GuardedData<Private, MeiliSearch>,
    body: web::Json<Value>,
    path: web::Path<AuthParam>,
    analytics: web::Data<dyn Analytics>,
) -> Result<HttpResponse, ResponseError> {
    let key = meilisearch
        // keep 8 first characters that are the ID of the API key.
        .update_key(&path.api_key[..8], body.into_inner())
        .await?;
    let res = KeyView::from_key(key, meilisearch.master_key());

    debug!("returns: {:?}", res);
    Ok(HttpResponse::Ok().json(res))
}

pub async fn delete_api_key(
    meilisearch: GuardedData<Private, MeiliSearch>,
    path: web::Path<AuthParam>,
    analytics: web::Data<dyn Analytics>,
) -> Result<HttpResponse, ResponseError> {
    // keep 8 first characters that are the ID of the API key.
    meilisearch.delete_key(&path.api_key[..8]).await?;

    Ok(HttpResponse::NoContent().json(()))
}

#[derive(Deserialize)]
pub struct AuthParam {
    api_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyView {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    key: String,
    actions: Vec<Action>,
    indexes: Vec<String>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl KeyView {
    fn from_key(key: Key, master_key: Option<&String>) -> Self {
        let generated_key = match master_key {
            Some(master_key) => generate_key(master_key, &key.id),
            None => generate_key("", &key.id),
        };

        KeyView {
            description: key.description,
            key: generated_key,
            actions: key.actions,
            indexes: key.indexes,
            expires_at: key.expires_at,
            created_at: key.created_at,
            updated_at: key.updated_at,
        }
    }
}

fn generate_key(master_key: &str, uid: &str) -> String {
    let key = format!("{}-{}", uid, master_key);
    let sha = Sha256::digest(key.as_bytes());
    format!("{}-{:x}", uid, sha)
}
