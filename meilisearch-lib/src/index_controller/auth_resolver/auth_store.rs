use std::borrow::Cow;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fs::{create_dir_all, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::str;

use chrono::{DateTime, Utc};
use heed::types::{ByteSlice, DecodeIgnore, Str};
use heed::{Database, Env, EnvOpenOptions, RwTxn};
use serde::{Deserialize, Serialize};

use super::error::{AuthResolverError, Result};
use super::{Action, Key};

const AUTH_STORE_SIZE: usize = 1_073_741_824; //1GiB
pub const KEY_ID_LENGTH: usize = 8;
const AUTH_DB_PATH: &str = "auth";
const KEY_DB_NAME: &str = "api-keys";
const ACTION_KEY_ID_INDEX_EXPIRATION_DB_NAME: &str = "action-keyid-index-expiration";

#[derive(Clone)]
pub struct HeedAuthStore {
    env: Env,
    keys: Database<ByteSlice, SerdeJsonCodec<Key>>,
    action_keyid_index_expiration: Database<ActionKeyIdCodec, SerdeJsonCodec<DateTime<Utc>>>,
}

impl HeedAuthStore {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().join(AUTH_DB_PATH);
        create_dir_all(&path)?;
        let mut options = EnvOpenOptions::new();
        options.map_size(AUTH_STORE_SIZE); // 1GB
        options.max_dbs(2);
        let env = options.open(path)?;
        let keys = env.create_database(Some(KEY_DB_NAME))?;
        let action_keyid_index_expiration =
            env.create_database(Some(ACTION_KEY_ID_INDEX_EXPIRATION_DB_NAME))?;
        Ok(Self {
            env,
            keys,
            action_keyid_index_expiration,
        })
    }

    pub fn put_api_key(&self, key: Key) -> Result<Key> {
        let mut wtxn = self.env.write_txn()?;
        self.keys.put(&mut wtxn, &key.id, &key)?;

        let id = key.id;
        // delete key from inverted database before refilling it.
        self.delete_key_from_inverted_db(&mut wtxn, &id)?;
        // create inverted database.
        let db = self.action_keyid_index_expiration;

        let no_index_restriction = key.indexes.contains(&"*".to_owned());
        for action in key.actions.iter() {
            if no_index_restriction {
                // If there is no index restriction we put None.
                db.put(&mut wtxn, &(&id, action, None), &key.expires_at)?;
            } else {
                // else we create a key for each index.
                for index in key.indexes.iter() {
                    db.put(&mut wtxn, &(&id, action, Some(&index)), &key.expires_at)?;
                }
            }
        }

        wtxn.commit()?;

        Ok(key)
    }

    pub fn get_api_key(&self, key: impl AsRef<str>) -> Result<Option<Key>> {
        let rtxn = self.env.read_txn()?;
        match try_split_array_at::<_, KEY_ID_LENGTH>(key.as_ref().as_bytes()) {
            Some((id, _)) => self.keys.get(&rtxn, &id).map_err(|e| e.into()),
            None => Ok(None),
        }
    }

    pub fn delete_api_key(&self, key: impl AsRef<str>) -> Result<bool> {
        let mut wtxn = self.env.write_txn()?;
        let existing = match try_split_array_at(key.as_ref().as_bytes()) {
            Some((id, _)) => {
                let existing = self.keys.delete(&mut wtxn, &id)?;
                self.delete_key_from_inverted_db(&mut wtxn, &id)?;
                existing
            }
            None => false,
        };
        wtxn.commit()?;

        Ok(existing)
    }

    pub fn list_api_keys(&self) -> Result<Vec<Key>> {
        let mut list = Vec::new();
        let rtxn = self.env.read_txn()?;
        for result in self.keys.remap_key_type::<DecodeIgnore>().iter(&rtxn)? {
            let (_, content) = result?;
            list.push(content);
        }
        Ok(list)
    }

    fn delete_key_from_inverted_db(
        &self,
        wtxn: &mut RwTxn,
        key: &[u8; KEY_ID_LENGTH],
    ) -> Result<()> {
        let mut iter = self
            .action_keyid_index_expiration
            .remap_types::<ByteSlice, DecodeIgnore>()
            .prefix_iter_mut(wtxn, key)?;
        while let Some(_) = iter.next().transpose()? {
            // safety: we don't keep references from inside the LMDB database.
            unsafe { iter.del_current()? };
        }

        Ok(())
    }
}

/// Heed codec allowing to encode/decode everithing that implement Serialize and Deserialize
/// in order to store it in heed.
/// This is obviously not the best approach and should never be used for big and numerous objects,
/// but it is a simple one.
pub struct SerdeJsonCodec<T>(std::marker::PhantomData<T>);

impl<'a, T> heed::BytesDecode<'a> for SerdeJsonCodec<T>
where
    T: Deserialize<'a> + 'a,
{
    type DItem = T;

    fn bytes_decode(bytes: &'a [u8]) -> Option<Self::DItem> {
        serde_json::from_slice(bytes).ok()
    }
}

impl<'a, T> heed::BytesEncode<'a> for SerdeJsonCodec<T>
where
    T: Serialize + 'a,
{
    type EItem = T;

    fn bytes_encode(item: &Self::EItem) -> Option<Cow<[u8]>> {
        serde_json::to_vec(item).map(|bytes| Cow::Owned(bytes)).ok()
    }
}

pub struct ActionKeyIdCodec;

impl<'a> heed::BytesDecode<'a> for ActionKeyIdCodec {
    type DItem = ([u8; KEY_ID_LENGTH], Action, Option<&'a str>);

    fn bytes_decode(bytes: &'a [u8]) -> Option<Self::DItem> {
        let (key_id, action_bytes) = try_split_array_at(bytes)?;
        let (action_bytes, index) = match try_split_array_at(action_bytes)? {
            (action, []) => (action, None),
            (action, index) => (action, Some(str::from_utf8(index).ok()?)),
        };
        let action = Action::from_repr(u8::from_be_bytes(action_bytes))?;

        Some((key_id, action, index))
    }
}

impl<'a> heed::BytesEncode<'a> for ActionKeyIdCodec {
    type EItem = (&'a [u8; KEY_ID_LENGTH], &'a Action, Option<&'a str>);

    fn bytes_encode((key_id, action, index): &Self::EItem) -> Option<Cow<[u8]>> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(*key_id);
        let action_bytes = u8::to_be_bytes(action.repr());
        bytes.extend_from_slice(&action_bytes);
        if let Some(index) = index {
            bytes.extend_from_slice(index.as_bytes());
        }

        Some(Cow::Owned(bytes))
    }
}

/// Divides one slice into two at an index, returns `None` if mid is out of bounds.
pub fn try_split_at<T>(slice: &[T], mid: usize) -> Option<(&[T], &[T])> {
    if mid <= slice.len() {
        Some(slice.split_at(mid))
    } else {
        None
    }
}

/// Divides one slice into an array and the tail at an index,
/// returns `None` if `N` is out of bounds.
pub fn try_split_array_at<T, const N: usize>(slice: &[T]) -> Option<([T; N], &[T])>
where
    [T; N]: for<'a> TryFrom<&'a [T]>,
{
    let (head, tail) = try_split_at(slice, N)?;
    let head = head.try_into().ok()?;
    Some((head, tail))
}
