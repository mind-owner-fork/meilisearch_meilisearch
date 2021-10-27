use log::debug;

use actix_web::{web, HttpRequest, HttpResponse};
use meilisearch_lib::index::{Settings, Unchecked};
use meilisearch_lib::index_controller::Update;
use meilisearch_lib::MeiliSearch;
use serde_json::json;

use crate::analytics::Analytics;
use crate::error::ResponseError;
use crate::extractors::authentication::{policies::*, GuardedData};

#[macro_export]
macro_rules! make_setting_route {
    ($route:literal, $type:ty, $attr:ident, $camelcase_attr:literal, $analytics_var:ident, $analytics:expr) => {
        pub mod $attr {
            use log::debug;
            use actix_web::{web, HttpResponse, HttpRequest, Resource};

            use meilisearch_lib::milli::update::Setting;
            use meilisearch_lib::{MeiliSearch, index::Settings, index_controller::Update};

            use crate::analytics::Analytics;
            use crate::error::ResponseError;
            use crate::extractors::authentication::{GuardedData, policies::*};

            pub async fn delete(
                meilisearch: GuardedData<Private, MeiliSearch>,
                index_uid: web::Path<String>,
            ) -> Result<HttpResponse, ResponseError> {
                let settings = Settings {
                    $attr: Setting::Reset,
                    ..Default::default()
                };
                let update = Update::Settings(settings);
                let update_status = meilisearch.register_update(index_uid.into_inner(), update, false).await?;
                debug!("returns: {:?}", update_status);
                Ok(HttpResponse::Accepted().json(serde_json::json!({ "updateId": update_status.id() })))
            }

            pub async fn update(
                meilisearch: GuardedData<Private, MeiliSearch>,
                index_uid: actix_web::web::Path<String>,
                body: actix_web::web::Json<Option<$type>>,
                req: HttpRequest,
                $analytics_var: web::Data<&'static dyn Analytics>,
            ) -> std::result::Result<HttpResponse, ResponseError> {
                let body = body.into_inner();

                $analytics(&body, &req);

                let settings = Settings {
                    $attr: match body {
                        Some(inner_body) => Setting::Set(inner_body),
                        None => Setting::Reset
                    },
                    ..Default::default()
                };

                let update = Update::Settings(settings);
                let update_status = meilisearch.register_update(index_uid.into_inner(), update, true).await?;
                debug!("returns: {:?}", update_status);
                Ok(HttpResponse::Accepted().json(serde_json::json!({ "updateId": update_status.id() })))
            }

            pub async fn get(
                meilisearch: GuardedData<Private, MeiliSearch>,
                index_uid: actix_web::web::Path<String>,
            ) -> std::result::Result<HttpResponse, ResponseError> {
                let settings = meilisearch.settings(index_uid.into_inner()).await?;
                debug!("returns: {:?}", settings);
                let mut json = serde_json::json!(&settings);
                let val = json[$camelcase_attr].take();
                Ok(HttpResponse::Ok().json(val))
            }

            pub fn resources() -> Resource {
                Resource::new($route)
                    .route(web::get().to(get))
                    .route(web::post().to(update))
                    .route(web::delete().to(delete))
            }
        }
    };
    ($route:literal, $type:ty, $attr:ident, $camelcase_attr:literal) => {
        make_setting_route!($route, $type, $attr, $camelcase_attr, _analytics, |_, _| {});
    };
}

make_setting_route!(
    "/filterable-attributes",
    std::collections::BTreeSet<String>,
    filterable_attributes,
    "filterableAttributes",
    analytics,
    |setting: &Option<std::collections::BTreeSet<String>>, req: &HttpRequest| {
        use serde_json::json;

        analytics.publish(
            "FilterableAttributes Updated".to_string(),
            json!({
                "total": setting.as_ref().map(|filter| filter.len()),
                "has_geo": setting.as_ref().map(|filter| filter.contains("_geo")).unwrap_or(false),
            }),
            Some(req),
        );
    }
);

make_setting_route!(
    "/sortable-attributes",
    std::collections::BTreeSet<String>,
    sortable_attributes,
    "sortableAttributes",
    analytics,
    |setting: &Option<std::collections::BTreeSet<String>>, req: &HttpRequest| {
        use serde_json::json;

        analytics.publish(
            "SortableAttributes Updated".to_string(),
            json!({
                "total": setting.as_ref().map(|sort| sort.len()),
                "has_geo": setting.as_ref().map(|sort| sort.contains("_geo")).unwrap_or(false),
            }),
            Some(req),
        );
    }
);

make_setting_route!(
    "/displayed-attributes",
    Vec<String>,
    displayed_attributes,
    "displayedAttributes"
);

make_setting_route!(
    "/searchable-attributes",
    Vec<String>,
    searchable_attributes,
    "searchableAttributes"
);

make_setting_route!(
    "/stop-words",
    std::collections::BTreeSet<String>,
    stop_words,
    "stopWords"
);

make_setting_route!(
    "/synonyms",
    std::collections::BTreeMap<String, Vec<String>>,
    synonyms,
    "synonyms"
);

make_setting_route!(
    "/distinct-attribute",
    String,
    distinct_attribute,
    "distinctAttribute"
);

make_setting_route!(
    "/ranking-rules",
    Vec<String>,
    ranking_rules,
    "rankingRules",
    analytics,
    |setting: &Option<Vec<String>>, req: &HttpRequest| {
        use serde_json::json;

        analytics.publish(
            "RankingRules Updated".to_string(),
            json!({
                "sort_position": setting.as_ref().map(|sort| sort.iter().position(|s| s == "sort")),
            }),
            Some(req),
        );
    }
);

macro_rules! generate_configure {
    ($($mod:ident),*) => {
        pub fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(
                web::resource("")
                .route(web::post().to(update_all))
                .route(web::get().to(get_all))
                .route(web::delete().to(delete_all)))
                $(.service($mod::resources()))*;
        }
    };
}

generate_configure!(
    filterable_attributes,
    sortable_attributes,
    displayed_attributes,
    searchable_attributes,
    distinct_attribute,
    stop_words,
    synonyms,
    ranking_rules
);

pub async fn update_all(
    meilisearch: GuardedData<Private, MeiliSearch>,
    index_uid: web::Path<String>,
    body: web::Json<Settings<Unchecked>>,
    req: HttpRequest,
    analytics: web::Data<&'static dyn Analytics>,
) -> Result<HttpResponse, ResponseError> {
    let settings = body.into_inner();

    analytics.publish(
        "Settings Updated".to_string(),
        json!({
           "ranking_rules": {
                "sort_position": settings.ranking_rules.as_ref().set().map(|sort| sort.iter().position(|s| s == "sort")),
            },
           "sortable_attributes": {
                "total": settings.sortable_attributes.as_ref().set().map(|sort| sort.len()),
                "has_geo": settings.sortable_attributes.as_ref().set().map(|sort| sort.iter().any(|s| s == "_geo")).unwrap_or(false),
            },
           "filterable_attributes": {
                "total": settings.filterable_attributes.as_ref().set().map(|filter| filter.len()),
                "has_geo": settings.filterable_attributes.as_ref().set().map(|filter| filter.iter().any(|s| s == "_geo")).unwrap_or(false),
            },
        }),
        Some(&req),
    );

    let update = Update::Settings(settings);
    let update_result = meilisearch
        .register_update(index_uid.into_inner(), update, true)
        .await?;
    let json = serde_json::json!({ "updateId": update_result.id() });
    debug!("returns: {:?}", json);
    Ok(HttpResponse::Accepted().json(json))
}

pub async fn get_all(
    data: GuardedData<Private, MeiliSearch>,
    index_uid: web::Path<String>,
) -> Result<HttpResponse, ResponseError> {
    let settings = data.settings(index_uid.into_inner()).await?;
    debug!("returns: {:?}", settings);
    Ok(HttpResponse::Ok().json(settings))
}

pub async fn delete_all(
    data: GuardedData<Private, MeiliSearch>,
    index_uid: web::Path<String>,
) -> Result<HttpResponse, ResponseError> {
    let settings = Settings::cleared();

    let update = Update::Settings(settings.into_unchecked());
    let update_result = data
        .register_update(index_uid.into_inner(), update, false)
        .await?;
    let json = serde_json::json!({ "updateId": update_result.id() });
    debug!("returns: {:?}", json);
    Ok(HttpResponse::Accepted().json(json))
}
