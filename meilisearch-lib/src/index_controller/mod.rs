use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use actix_web::error::PayloadError;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::Stream;
use futures::StreamExt;
use log::info;
use meilisearch_tasks::create_task_store;
use meilisearch_tasks::task::{DocumentAdditionMergeStrategy, DocumentDeletion, Task, TaskContent, TaskId};
use meilisearch_tasks::task_store::{TaskFilter, TaskStore};
use milli::update::IndexDocumentsMethod;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::spawn_blocking;
use tokio::time::sleep;
use uuid::Uuid;

use dump_actor::DumpActorHandle;
pub use dump_actor::{DumpInfo, DumpStatus};
use snapshot::load_snapshot;

use crate::document_formats::read_csv;
use crate::document_formats::read_json;
use crate::document_formats::read_ndjson;
use crate::index::error::Result as IndexResult;
use crate::index::{
    Checked, Document, IndexMeta, IndexStats, SearchQuery, SearchResult, Settings, Unchecked,
};
use crate::index_controller::index_resolver::create_index_resolver;
//use crate::index_controller::snapshot::SnapshotService;
use crate::options::IndexerOpts;
use error::Result;

use self::dump_actor::load_dump;
//use self::index_resolver::error::IndexResolverError;
use self::index_resolver::HardStateIndexResolver;
use self::update_file_store::UpdateFileStore;
//use self::updates::UpdateMsg;

mod dump_actor;
pub mod error;
mod index_resolver;
mod snapshot;
pub mod update_file_store;
pub mod updates;

/// Concrete implementation of the IndexController, exposed by meilisearch-lib
pub type MeiliSearch = IndexController;

pub type Payload = Box<
    dyn Stream<Item = std::result::Result<Bytes, PayloadError>> + Send + Sync + 'static + Unpin,
>;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct IndexMetadata {
    #[serde(skip)]
    pub uuid: Uuid,
    pub uid: String,
    name: String,
    #[serde(flatten)]
    pub meta: IndexMeta,
}

#[derive(Clone, Debug)]
pub struct IndexSettings {
    pub uid: Option<String>,
    pub primary_key: Option<String>,
}

#[derive(Clone)]
pub struct IndexController {
    index_resolver: Arc<HardStateIndexResolver>,
    task_store: TaskStore,
    dump_handle: dump_actor::DumpActorHandleImpl,
    update_file_store: UpdateFileStore,
}

#[derive(Debug)]
pub enum DocumentAdditionFormat {
    Json,
    Csv,
    Ndjson,
}

impl fmt::Display for DocumentAdditionFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DocumentAdditionFormat::Json => write!(f, "json"),
            DocumentAdditionFormat::Ndjson => write!(f, "ndjson"),
            DocumentAdditionFormat::Csv => write!(f, "csv"),
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub database_size: u64,
    pub last_update: Option<DateTime<Utc>>,
    pub indexes: BTreeMap<String, IndexStats>,
}

#[allow(clippy::large_enum_variant)]
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub enum Update {
    DeleteDocuments(Vec<String>),
    ClearDocuments,
    Settings(Settings<Unchecked>),
    DocumentAddition {
        #[derivative(Debug = "ignore")]
        payload: Payload,
        primary_key: Option<String>,
        method: IndexDocumentsMethod,
        format: DocumentAdditionFormat,
    },
    DeleteIndex,
}

#[derive(Default, Debug)]
pub struct IndexControllerBuilder {
    max_index_size: Option<usize>,
    max_update_store_size: Option<usize>,
    snapshot_dir: Option<PathBuf>,
    import_snapshot: Option<PathBuf>,
    snapshot_interval: Option<Duration>,
    ignore_snapshot_if_db_exists: bool,
    ignore_missing_snapshot: bool,
    schedule_snapshot: bool,
    dump_src: Option<PathBuf>,
    dump_dst: Option<PathBuf>,
}

impl IndexControllerBuilder {
    pub fn build(
        self,
        db_path: impl AsRef<Path>,
        indexer_options: IndexerOpts,
    ) -> anyhow::Result<MeiliSearch> {
        let index_size = self
            .max_index_size
            .ok_or_else(|| anyhow::anyhow!("Missing index size"))?;
        let update_store_size = self
            .max_index_size
            .ok_or_else(|| anyhow::anyhow!("Missing update database size"))?;

        if let Some(ref path) = self.import_snapshot {
            info!("Loading from snapshot {:?}", path);
            load_snapshot(
                db_path.as_ref(),
                path,
                self.ignore_snapshot_if_db_exists,
                self.ignore_missing_snapshot,
            )?;
        } else if let Some(ref src_path) = self.dump_src {
            load_dump(
                db_path.as_ref(),
                src_path,
                index_size,
                update_store_size,
                &indexer_options,
            )?;
        }

        std::fs::create_dir_all(db_path.as_ref())?;

        let index_resolver = Arc::new(create_index_resolver(
            &db_path,
            index_size,
            &indexer_options,
        )?);

        let task_store = create_task_store(
            &db_path,
            update_store_size,
            index_resolver.clone()).map_err(|e| anyhow::anyhow!(e))?;

        //let dump_path = self
            //.dump_dst
            //.ok_or_else(|| anyhow::anyhow!("Missing dump directory path"))?;
        //let dump_handle = dump_actor::DumpActorHandleImpl::new(
            //dump_path,
            //index_resolver.clone(),
            //task_store,
            //index_size,
            //update_store_size,
        //)?;

        let (sender, _) = mpsc::channel(1);
        let dump_handle = dump_actor::DumpActorHandleImpl { sender };

        let update_file_store = UpdateFileStore::new(&db_path)?;

        //if self.schedule_snapshot {
            //let snapshot_service = SnapshotService::new(
                //index_resolver.clone(),
                //task_store,
                //self.snapshot_interval
                    //.ok_or_else(|| anyhow::anyhow!("Snapshot interval not provided."))?,
                //self.snapshot_dir
                    //.ok_or_else(|| anyhow::anyhow!("Snapshot path not provided."))?,
                //db_path
                    //.as_ref()
                    //.file_name()
                    //.map(|n| n.to_owned().into_string().expect("invalid path"))
                    //.unwrap_or_else(|| String::from("data.ms")),
            //);

            //tokio::task::spawn(snapshot_service.run());
        //}

        Ok(IndexController {
            index_resolver,
            task_store,
            dump_handle,
            update_file_store,
        })
    }

    /// Set the index controller builder's max update store size.
    pub fn set_max_update_store_size(&mut self, max_update_store_size: usize) -> &mut Self {
        self.max_update_store_size.replace(max_update_store_size);
        self
    }

    pub fn set_max_index_size(&mut self, size: usize) -> &mut Self {
        self.max_index_size.replace(size);
        self
    }

    /// Set the index controller builder's snapshot path.
    pub fn set_snapshot_dir(&mut self, snapshot_dir: PathBuf) -> &mut Self {
        self.snapshot_dir.replace(snapshot_dir);
        self
    }

    /// Set the index controller builder's ignore snapshot if db exists.
    pub fn set_ignore_snapshot_if_db_exists(
        &mut self,
        ignore_snapshot_if_db_exists: bool,
    ) -> &mut Self {
        self.ignore_snapshot_if_db_exists = ignore_snapshot_if_db_exists;
        self
    }

    /// Set the index controller builder's ignore missing snapshot.
    pub fn set_ignore_missing_snapshot(&mut self, ignore_missing_snapshot: bool) -> &mut Self {
        self.ignore_missing_snapshot = ignore_missing_snapshot;
        self
    }

    /// Set the index controller builder's dump src.
    pub fn set_dump_src(&mut self, dump_src: PathBuf) -> &mut Self {
        self.dump_src.replace(dump_src);
        self
    }

    /// Set the index controller builder's dump dst.
    pub fn set_dump_dst(&mut self, dump_dst: PathBuf) -> &mut Self {
        self.dump_dst.replace(dump_dst);
        self
    }

    /// Set the index controller builder's import snapshot.
    pub fn set_import_snapshot(&mut self, import_snapshot: PathBuf) -> &mut Self {
        self.import_snapshot.replace(import_snapshot);
        self
    }

    /// Set the index controller builder's snapshot interval sec.
    pub fn set_snapshot_interval(&mut self, snapshot_interval: Duration) -> &mut Self {
        self.snapshot_interval = Some(snapshot_interval);
        self
    }

    /// Set the index controller builder's schedule snapshot.
    pub fn set_schedule_snapshot(&mut self) -> &mut Self {
        self.schedule_snapshot = true;
        self
    }
}

impl IndexController {
    pub fn builder() -> IndexControllerBuilder {
        IndexControllerBuilder::default()
    }

    pub async fn register_update(
        &self,
        uid: String,
        update: Update,
    ) -> Result<Task> {
        let content = match update {
            Update::DeleteDocuments(ids) => TaskContent::DocumentDeletion(DocumentDeletion::Ids(ids)),
            Update::ClearDocuments => TaskContent::DocumentDeletion(DocumentDeletion::Clear),
            Update::Settings(_) => TaskContent::SettingsUpdate,
            Update::DocumentAddition { mut payload, primary_key, format, .. } => {
                let mut buffer = Vec::new();
                while let Some(bytes) = payload.next().await {
                    match bytes {
                        Ok(bytes) => {
                            buffer.extend_from_slice(&bytes);
                        },
                        Err(_e) => todo!("handle payload errors"),
                    }
                }
                let (content_uuid, mut update_file) = self.update_file_store.new_update().unwrap();
                let documents_count = tokio::task::spawn_blocking(move || -> Result<_> {
                    // check if the payload is empty, and return an error
                    if buffer.is_empty() {
                        todo!("empty payload error")
                        //return Err(UpdateLoopError::MissingPayload(format));
                    }

                    let reader = Cursor::new(buffer);
                    let count = match format {
                        DocumentAdditionFormat::Json => read_json(reader, &mut *update_file).unwrap(),
                        DocumentAdditionFormat::Csv => read_csv(reader, &mut *update_file).unwrap(),
                        DocumentAdditionFormat::Ndjson => read_ndjson(reader, &mut *update_file).unwrap(),
                    };

                    update_file.persist().unwrap();

                    Ok(count)
                })
                .await.unwrap().unwrap();

                TaskContent::DocumentAddition {
                    content_uuid,
                    merge_strategy: DocumentAdditionMergeStrategy::ReplaceDocument,
                    primary_key,
                    documents_count,
                }
            },
            Update::DeleteIndex => TaskContent::IndexDeletion,
        };

        let task = self.task_store.register(uid, content).await.unwrap();

        Ok(task)
    }

    pub async fn get_task(&self, id: TaskId, filter: Option<TaskFilter>) -> Result<Task> {
        let task = self.task_store.get_task(id, filter).await.unwrap().unwrap();
        Ok(task)
    }

    pub async fn list_tasks(&self, filter: Option<TaskFilter>) -> Result<Vec<Task>> {
        let tasks = self.task_store.list_tasks(filter, 20, None).await.unwrap();
        Ok(tasks)
    }

    pub async fn list_indexes(&self) -> Result<Vec<IndexMetadata>> {
        todo!()
        //let indexes = self.index_resolver.list().await?;
        //let mut ret = Vec::new();
        //for (uid, index) in indexes {
            //let meta = index.meta()?;
            //let meta = IndexMetadata {
                //uuid: index.uuid,
                //name: uid.clone(),
                //uid,
                //meta,
            //};
            //ret.push(meta);
        //}

        //Ok(ret)
    }

    pub async fn settings(&self, uid: String) -> Result<Settings<Checked>> {
        let index = self.index_resolver.get_index(uid).await?;
        let settings = spawn_blocking(move || index.settings()).await??;
        Ok(settings)
    }

    pub async fn documents(
        &self,
        uid: String,
        offset: usize,
        limit: usize,
        attributes_to_retrieve: Option<Vec<String>>,
    ) -> Result<Vec<Document>> {
        let index = self.index_resolver.get_index(uid).await?;
        let documents =
            spawn_blocking(move || index.retrieve_documents(offset, limit, attributes_to_retrieve))
                .await??;
        Ok(documents)
    }

    pub async fn document(
        &self,
        uid: String,
        doc_id: String,
        attributes_to_retrieve: Option<Vec<String>>,
    ) -> Result<Document> {
        let index = self.index_resolver.get_index(uid).await?;
        let document =
            spawn_blocking(move || index.retrieve_document(doc_id, attributes_to_retrieve))
                .await??;
        Ok(document)
    }

    pub async fn update_index(
        &self,
        uid: String,
        mut index_settings: IndexSettings,
    ) -> Result<IndexMetadata> {
        index_settings.uid.take();

        let index = self.index_resolver.get_index(uid.clone()).await?;
        let uuid = index.uuid();
        let meta =
            spawn_blocking(move || index.update_primary_key(index_settings.primary_key)).await??;
        let meta = IndexMetadata {
            uuid,
            name: uid.clone(),
            uid,
            meta,
        };
        Ok(meta)
    }

    pub async fn search(&self, uid: String, query: SearchQuery) -> Result<SearchResult> {
        let index = self.index_resolver.get_index(uid.clone()).await?;
        let result = spawn_blocking(move || index.perform_search(query)).await??;
        Ok(result)
    }

    pub async fn get_index(&self, uid: String) -> Result<IndexMetadata> {
        let index = self.index_resolver.get_index(uid.clone()).await?;
        let uuid = index.uuid();
        let meta = spawn_blocking(move || index.meta()).await??;
        let meta = IndexMetadata {
            uuid,
            name: uid.clone(),
            uid,
            meta,
        };
        Ok(meta)
    }

    pub async fn get_index_stats(&self, _uid: String) -> Result<IndexStats> {
        todo!()
        //let update_infos = UpdateMsg::get_info(&self.update_sender).await?;
        //let index = self.index_resolver.get_index(uid).await?;
        //let uuid = index.uuid;
        //let mut stats = spawn_blocking(move || index.stats()).await??;
        //// Check if the currently indexing update is from our index.
        //stats.is_indexing = Some(Some(uuid) == update_infos.processing);
        //Ok(stats)
    }

    pub async fn get_all_stats(&self) -> Result<Stats> {
        todo!()
        //let update_infos = UpdateMsg::get_info(&self.update_sender).await?;
        //let mut database_size = self.index_resolver.get_uuids_size().await? + update_infos.size;
        //let mut last_update: Option<DateTime<_>> = None;
        //let mut indexes = BTreeMap::new();

        //for (index_uid, index) in self.index_resolver.list().await? {
            //let uuid = index.uuid;
            //let (mut stats, meta) = spawn_blocking::<_, IndexResult<_>>(move || {
                //let stats = index.stats()?;
                //let meta = index.meta()?;
                //Ok((stats, meta))
            //})
            //.await??;

            //database_size += stats.size;

            //last_update = last_update.map_or(Some(meta.updated_at), |last| {
                //Some(last.max(meta.updated_at))
            //});

            //// Check if the currently indexing update is from our index.
            //stats.is_indexing = Some(Some(uuid) == update_infos.processing);

            //indexes.insert(index_uid, stats);
        //}

        //Ok(Stats {
            //database_size,
            //last_update,
            //indexes,
        //})
    }

    pub async fn create_dump(&self) -> Result<DumpInfo> {
        Ok(self.dump_handle.create_dump().await?)
    }

    pub async fn dump_info(&self, uid: String) -> Result<DumpInfo> {
        Ok(self.dump_handle.dump_info(uid).await?)
    }

    pub async fn create_index(
        &self,
        uid: String,
        primary_key: Option<String>,
    ) -> Result<IndexMetadata> {
        let index = self
            .index_resolver
            .get_or_create_index(uid.clone(), primary_key)
            .await?;
        let meta = spawn_blocking(move || -> IndexResult<_> {
            let meta = index.meta()?;
            let meta = IndexMetadata {
                uuid: index.uuid(),
                uid: uid.clone(),
                name: uid,
                meta,
            };
            Ok(meta)
        })
        .await??;

        Ok(meta)
    }
}

pub async fn get_arc_ownership_blocking<T>(mut item: Arc<T>) -> T {
    loop {
        match Arc::try_unwrap(item) {
            Ok(item) => return item,
            Err(item_arc) => {
                item = item_arc;
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use futures::future::ok;
    use mockall::predicate::eq;
    use tokio::sync::mpsc;

    use crate::index::error::Result as IndexResult;
    use crate::index::test::Mocker;
    use crate::index::Index;
    use crate::index_controller::dump_actor::MockDumpActorHandle;
    use crate::index_controller::index_resolver::index_store::MockIndexStore;
    use crate::index_controller::index_resolver::uuid_store::MockUuidStore;

    use super::updates::UpdateSender;
    use super::*;

    impl<D: DumpActorHandle> IndexController<MockUuidStore, MockIndexStore, D> {
        pub fn mock(
            index_resolver: IndexResolver<MockUuidStore, MockIndexStore>,
            update_sender: UpdateSender,
            dump_handle: D,
        ) -> Self {
            IndexController {
                index_resolver: Arc::new(index_resolver),
                update_sender,
                dump_handle: Arc::new(dump_handle),
            }
        }
    }

    #[actix_rt::test]
    async fn test_search_simple() {
        let index_uid = "test";
        let index_uuid = Uuid::new_v4();
        let query = SearchQuery {
            q: Some(String::from("hello world")),
            offset: Some(10),
            limit: 0,
            attributes_to_retrieve: Some(vec!["string".to_owned()].into_iter().collect()),
            attributes_to_crop: None,
            crop_length: 18,
            attributes_to_highlight: None,
            matches: true,
            filter: None,
            sort: None,
            facets_distribution: None,
        };

        let result = SearchResult {
            hits: vec![],
            nb_hits: 29,
            exhaustive_nb_hits: true,
            query: "hello world".to_string(),
            limit: 24,
            offset: 0,
            processing_time_ms: 50,
            facets_distribution: None,
            exhaustive_facets_count: Some(true),
        };

        let mut uuid_store = MockUuidStore::new();
        uuid_store
            .expect_get_uuid()
            .with(eq(index_uid.to_owned()))
            .returning(move |s| Box::pin(ok((s, Some(index_uuid)))));

        let mut index_store = MockIndexStore::new();
        let result_clone = result.clone();
        let query_clone = query.clone();
        index_store
            .expect_get()
            .with(eq(index_uuid))
            .returning(move |_uuid| {
                let result = result_clone.clone();
                let query = query_clone.clone();
                let mocker = Mocker::default();
                mocker
                    .when::<SearchQuery, IndexResult<SearchResult>>("perform_search")
                    .once()
                    .then(move |q| {
                        assert_eq!(&q, &query);
                        Ok(result.clone())
                    });
                let index = Index::faux(mocker);
                Box::pin(ok(Some(index)))
            });

        let index_resolver = IndexResolver::new(uuid_store, index_store);
        let (update_sender, _) = mpsc::channel(1);
        let dump_actor = MockDumpActorHandle::new();
        let index_controller = IndexController::mock(index_resolver, update_sender, dump_actor);

        let r = index_controller
            .search(index_uid.to_owned(), query.clone())
            .await
            .unwrap();
        assert_eq!(r, result);
    }
}
