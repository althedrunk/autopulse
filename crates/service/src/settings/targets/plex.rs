use super::{Request, RequestBuilderPerform};
use crate::settings::path_filter::PathFilter;
use crate::settings::rewrite::Rewrite;
use crate::settings::targets::{TargetOutcome, TargetProcess};
use anyhow::Context;
use autopulse_database::models::ScanEvent;
use autopulse_utils::{get_url, RuntimePath};
use reqwest::header;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{debug, error, trace, warn};

#[derive(Serialize, Deserialize, Clone)]
pub struct Plex {
    /// URL to the Plex server
    pub url: String,
    /// API token for the Plex server
    pub token: String,
    /// Whether to refresh metadata of the file (default: false)
    #[serde(default)]
    pub refresh: bool,
    /// Whether to analyze the file (default: false)
    #[serde(default)]
    pub analyze: bool,
    /// Empty library trash when Plex reports scan completion (default: false).
    /// Removes all unavailable items in each scanned library, not just the scanned paths.
    #[serde(default)]
    pub empty_trash: bool,
    /// Rewrite path for the file
    pub rewrite: Option<Rewrite>,
    /// Path filter matched against the target-rewritten path.
    #[serde(default)]
    pub filter: PathFilter,
    /// HTTP request options
    #[serde(default)]
    pub request: Request,
    /// Confirm each file shows up in the library after it is scanned, and
    /// report files that do not as failed so they are retried (default: false).
    ///
    /// Plex silently drops a refresh request that arrives while it is already
    /// scanning the library, so with this enabled scans are sent one folder
    /// at a time, only once the library is idle, and each is waited on before
    /// the next. Pair it with `opts.max_retries` and `opts.max_retry_delay`
    /// to decide how long a missing file keeps being retried.
    #[serde(default)]
    pub verify: bool,
    /// With `verify`, seconds to wait for a scan that is already running to
    /// finish before sending ours (default: 600)
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: u64,
    /// With `verify`, seconds to wait for our scan to finish before looking
    /// the files up anyway (default: 900)
    #[serde(default = "default_scan_timeout")]
    pub scan_timeout: u64,
}

const fn default_idle_timeout() -> u64 {
    600
}

const fn default_scan_timeout() -> u64 {
    900
}

/// How often to poll Plex while waiting on a library scan.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// How long to watch for a sent scan to start. Small folders can be scanned
/// between two polls, so a scan that is never seen is not an error: the
/// library lookup that follows is the real check.
const SCAN_START_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Media {
    #[serde(rename = "Part")]
    pub part: Vec<Part>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Part {
    // pub id: i64,
    pub key: String,
    // pub duration: Option<i64>,
    pub file: String,
    // pub size: i64,
    // pub audio_profile: Option<String>,
    // pub container: Option<String>,
    // pub video_profile: Option<String>,
    // pub has_thumbnail: Option<String>,
    // pub has64bit_offsets: Option<bool>,
    // pub optimized_for_streaming: Option<bool>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub key: String,
    #[serde(rename = "Media")]
    pub media: Option<Vec<Media>>,
    #[serde(rename = "type")]
    pub t: String,
}

#[doc(hidden)]
#[derive(Deserialize, Clone, Debug)]
struct Location {
    path: String,
}

#[doc(hidden)]
#[derive(Deserialize, Clone, Debug)]
struct Library {
    title: String,
    key: String,
    /// `movie`, `show`, `artist` or `photo`
    #[serde(rename = "type", default)]
    kind: Option<String>,
    refreshing: Option<bool>,
    #[serde(rename = "scannedAt")]
    scanned_at: Option<u64>,
    #[serde(rename = "Location")]
    location: Vec<Location>,
}

/// A library's current scan state, for display.
#[derive(Serialize, Clone, Debug)]
pub struct LibraryState {
    pub title: String,
    /// `movie`, `show`, `artist` or `photo`
    pub kind: Option<String>,
    /// Whether Plex is scanning the library right now; `None` if not reported.
    pub refreshing: Option<bool>,
}

/// `(event id, path)` pairs for the files of one folder.
type FolderFiles = Vec<(String, String)>;
/// A library and the folders to scan in it, in first-seen order.
type LibraryPlan = (Library, Vec<(String, FolderFiles)>);

struct LibraryCleanup {
    scanned_at: Option<u64>,
    event_ids: HashSet<String>,
    scan_failed: bool,
}

#[doc(hidden)]
#[derive(Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct LibraryMediaContainer {
    directory: Option<Vec<Library>>,
    metadata: Option<Vec<Metadata>>,
}

#[doc(hidden)]
#[derive(Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct SearchResult {
    metadata: Option<Metadata>,
}

#[doc(hidden)]
#[derive(Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct SearchLibraryMediaContainer {
    #[serde(default)]
    search_result: Vec<SearchResult>,
}

#[doc(hidden)]
#[derive(Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct LibraryResponse {
    media_container: LibraryMediaContainer,
}

#[doc(hidden)]
#[derive(Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct SearchLibraryResponse {
    media_container: SearchLibraryMediaContainer,
}

fn path_matches(part_file: &str, path: &str) -> bool {
    let part_file = RuntimePath::new(part_file);
    let path = RuntimePath::new(path);

    if path.is_directory() {
        part_file.starts_with(path)
    } else {
        part_file.equals(path)
    }
}

fn has_matching_media(media: &[Media], path: &str) -> bool {
    media.iter().any(|media_item| {
        media_item
            .part
            .iter()
            .any(|part| path_matches(&part.file, path))
    })
}

fn scan_directory(path: &str) -> &str {
    RuntimePath::new(path).parent_or_self().as_str()
}

impl Plex {
    fn get_client(&self) -> anyhow::Result<reqwest::Client> {
        let mut headers = header::HeaderMap::new();

        headers.insert("X-Plex-Token", self.token.parse()?);
        headers.insert("Accept", "application/json".parse()?);

        self.request
            .client_builder(headers)
            .build()
            .map_err(Into::into)
    }

    async fn libraries(&self) -> anyhow::Result<Vec<Library>> {
        let client = self.get_client()?;
        let url = get_url(&self.url)?.join("library/sections")?;

        let res = client.get(url).perform().await?;

        let libraries: LibraryResponse = res.json().await?;

        Ok(libraries.media_container.directory.unwrap_or_default())
    }

    fn get_libraries(&self, libraries: &[Library], path: &str) -> Vec<Library> {
        let event_path = RuntimePath::new(path);
        let mut matches: Vec<(usize, &Library)> = vec![];

        for library in libraries {
            for location in &library.location {
                let location_path = RuntimePath::new(&location.path);
                if event_path.starts_with(location_path) {
                    matches.push((location_path.component_count(), library));
                }
            }
        }

        // Most-specific (highest component count) match first
        matches.sort_by(|(components_a, _), (components_b, _)| components_b.cmp(components_a));

        matches
            .into_iter()
            .map(|(_, library)| library.clone())
            .collect()
    }

    async fn get_episodes(&self, key: &str) -> anyhow::Result<LibraryResponse> {
        let client = self.get_client()?;

        // remove last part of the key
        let key = key.rsplit_once('/').map(|x| x.0).unwrap_or(key);

        let url = get_url(&self.url)?.join(&format!("{key}/allLeaves"))?;

        let res = client.get(url).perform().await?;

        let lib: LibraryResponse = res.json().await?;

        Ok(lib)
    }

    fn get_search_term(&self, path: &str) -> anyhow::Result<String> {
        let parent_or_directory = RuntimePath::new(path).parent_or_self();
        let components = parent_or_directory.normal_components().collect::<Vec<_>>();

        let chosen = components
            .iter()
            .rev()
            .copied()
            .find(|component| !component.contains("Season") && !component.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                // All components were "Season N": use normalized components,
                // not raw source, to keep drive letters/UNC/backslashes out
                components.join(" ")
            });

        Ok(chosen
            .split_whitespace()
            .filter(|part| {
                ["(", ")", "[", "]", "{", "}"]
                    .iter()
                    .all(|character| !part.contains(character))
            })
            .collect::<Vec<_>>()
            .join(" "))
    }

    async fn search_items(&self, _library: &Library, path: &str) -> anyhow::Result<Vec<Metadata>> {
        let client = self.get_client()?;
        // let mut url = get_url(&self.url)?.join(&format!("library/sections/{}/all", library.key))?;

        let mut results = vec![];

        let rel_path = path.to_string();

        trace!("searching for item with relative path: {}", rel_path);

        let mut search_term = self.get_search_term(&rel_path)?;

        while !search_term.is_empty() {
            let mut url = get_url(&self.url)?.join("library/search")?;

            url.query_pairs_mut().append_pair("includeCollections", "1");
            url.query_pairs_mut()
                .append_pair("includeExternalMedia", "1");
            url.query_pairs_mut()
                .append_pair("searchTypes", "movies,people,tv");
            url.query_pairs_mut().append_pair("limit", "100");

            trace!("searching for item with term: {}", search_term);

            url.query_pairs_mut()
                // .append_pair("title", search_term.as_str());
                .append_pair("query", search_term.as_str());

            let res = client.get(url).perform().await?;

            let lib: SearchLibraryResponse = res.json().await?;

            let mut metadata = lib
                .media_container
                .search_result
                .into_iter()
                .filter_map(|s| s.metadata)
                .collect::<Vec<_>>();

            // sort episodes then movies to the front, then the rest
            metadata.sort_by(|a, b| {
                if a.t == "episode" && b.t != "episode" {
                    std::cmp::Ordering::Less
                } else if a.t != "episode" && b.t == "episode" {
                    std::cmp::Ordering::Greater
                } else if a.t == "movie" && b.t != "movie" && b.t != "episode" {
                    std::cmp::Ordering::Less
                } else if a.t != "movie" && a.t != "episode" && b.t == "movie" {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            });

            for item in &metadata {
                if item.t == "show" {
                    let episodes = self.get_episodes(&item.key).await?;

                    if let Some(episode_metadata) = episodes.media_container.metadata {
                        for episode in episode_metadata {
                            if let Some(media) = &episode.media {
                                if has_matching_media(media, path) {
                                    results.push(episode.clone());
                                }
                            }
                        }
                    }
                } else if let Some(media) = &item.media {
                    // For movies and other content types
                    if has_matching_media(media, path) {
                        results.push(item.clone());
                    }
                }
            }

            trace!(
                "found {} out of {} items matching search",
                results.len(),
                metadata.len()
            );

            if results.is_empty() {
                let mut search_parts = search_term.split_whitespace().collect::<Vec<_>>();
                search_parts.pop();
                search_term = search_parts.join(" ");
            } else {
                break;
            }
        }

        // if show + episode then remove duplicates
        results.dedup_by_key(|item| item.key.clone());

        Ok(results)
    }

    async fn _get_items(&self, library: &Library, path: &str) -> anyhow::Result<Vec<Metadata>> {
        let client = self.get_client()?;
        let url = get_url(&self.url)?.join(&format!("library/sections/{}/all", library.key))?;

        let res = client.get(url).perform().await?;

        let lib: LibraryResponse = res.json().await?;

        let mut parts = vec![];

        // TODO: Reduce the amount of data needed to be searched
        for item in lib.media_container.metadata.unwrap_or_default() {
            match item.t.as_str() {
                "show" => {
                    let episodes = self.get_episodes(&item.key).await?;

                    for episode in episodes.media_container.metadata.unwrap_or_default() {
                        if let Some(media) = &episode.media {
                            if has_matching_media(media, path) {
                                parts.push(episode.clone());
                            }
                        }
                    }
                }
                _ => {
                    if let Some(media) = &item.media {
                        if has_matching_media(media, path) {
                            parts.push(item.clone());
                        }
                    }
                }
            }
        }

        Ok(parts)
    }

    async fn refresh_item(&self, key: &str) -> anyhow::Result<()> {
        let client = self.get_client()?;
        let url = get_url(&self.url)?.join(&format!("{key}/refresh"))?;

        client.put(url).perform().await.map(|_| ())
    }

    async fn analyze_item(&self, key: &str) -> anyhow::Result<()> {
        let client = self.get_client()?;
        let url = get_url(&self.url)?.join(&format!("{key}/analyze"))?;

        client.put(url).perform().await.map(|_| ())
    }

    async fn scan(&self, ev: &ScanEvent, library: &Library) -> anyhow::Result<()> {
        let client = self.get_client()?;
        let mut url =
            get_url(&self.url)?.join(&format!("library/sections/{}/refresh", library.key))?;

        let ev_path = ev.get_path(&self.rewrite);
        url.query_pairs_mut()
            .append_pair("path", scan_directory(&ev_path));

        client.get(url).perform().await.map(|_| ())
    }

    /// Plex item type to list for a library, or `None` when items of that
    /// library cannot be looked up by file.
    fn item_type(library: &Library) -> Option<&'static str> {
        match library.kind.as_deref() {
            Some("movie") => Some("1"),
            Some("show") => Some("4"),
            Some("artist") => Some("10"),
            _ => None,
        }
    }

    /// Items in `library` with media at `path`. Plex's `file` filter is a
    /// substring match, so results are narrowed to exact matches here.
    ///
    /// Returns `None` when the library type cannot be looked up by file.
    async fn find_by_file(
        &self,
        library: &Library,
        path: &str,
    ) -> anyhow::Result<Option<Vec<Metadata>>> {
        let Some(item_type) = Self::item_type(library) else {
            return Ok(None);
        };

        let client = self.get_client()?;
        let mut url = get_url(&self.url)?.join(&format!("library/sections/{}/all", library.key))?;
        url.query_pairs_mut()
            .append_pair("type", item_type)
            .append_pair("file", path);

        let res = client.get(url).perform().await?;
        let lib: LibraryResponse = res.json().await?;

        Ok(Some(
            lib.media_container
                .metadata
                .unwrap_or_default()
                .into_iter()
                .filter(|item| {
                    item.media
                        .as_deref()
                        .is_some_and(|media| has_matching_media(media, path))
                })
                .collect(),
        ))
    }

    async fn is_refreshing(&self, key: &str) -> anyhow::Result<bool> {
        let library = self
            .libraries()
            .await?
            .into_iter()
            .find(|library| library.key == key)
            .context("scanned library no longer exists")?;

        library
            .refreshing
            .context("Plex did not report the library scan status")
    }

    /// Waits for any scan of the library to finish. Returns `false` if it is
    /// still scanning after `timeout`.
    async fn wait_until_idle(
        &self,
        key: &str,
        timeout: std::time::Duration,
    ) -> anyhow::Result<bool> {
        let started = tokio::time::Instant::now();

        while self.is_refreshing(key).await? {
            if started.elapsed() >= timeout {
                return Ok(false);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }

        Ok(true)
    }

    /// Waits for a scan we just requested to start and finish. Returns
    /// `false` if it is still running after `timeout`.
    async fn wait_for_scan(&self, key: &str, timeout: std::time::Duration) -> anyhow::Result<bool> {
        let started = tokio::time::Instant::now();
        let mut observed_scan = false;

        loop {
            tokio::time::sleep(POLL_INTERVAL).await;

            if self.is_refreshing(key).await? {
                observed_scan = true;
            } else if observed_scan || started.elapsed() >= SCAN_START_GRACE {
                return Ok(true);
            }

            if started.elapsed() >= timeout {
                return Ok(false);
            }
        }
    }

    async fn scan_folder(&self, library: &Library, directory: &str) -> anyhow::Result<()> {
        let client = self.get_client()?;
        let mut url =
            get_url(&self.url)?.join(&format!("library/sections/{}/refresh", library.key))?;
        url.query_pairs_mut().append_pair("path", directory);

        client.get(url).perform().await.map(|_| ())
    }

    async fn empty_trash_now(&self, key: &str) -> anyhow::Result<()> {
        let client = self.get_client()?;
        let url = get_url(&self.url)?.join(&format!("library/sections/{key}/emptyTrash"))?;
        client.put(url).perform().await.map(|_| ())
    }

    /// Runs `refresh`/`analyze` on items found during verification. Returns
    /// a failure note if any of them failed.
    async fn refresh_and_analyze(&self, items: &[Metadata]) -> Option<String> {
        let mut failures = vec![];

        for item in items {
            if self.refresh {
                if let Err(e) = self.refresh_item(&item.key).await {
                    failures.push(format!("refresh of '{}' failed: {e}", item.key));
                }
            }
            if self.analyze {
                if let Err(e) = self.analyze_item(&item.key).await {
                    failures.push(format!("analyze of '{}' failed: {e}", item.key));
                }
            }
        }

        (!failures.is_empty()).then(|| failures.join("; "))
    }

    /// `verify` mode: scan each affected folder once, one at a time while the
    /// library is idle, then look every file up in the library.
    async fn process_verified(&self, evs: &[&ScanEvent]) -> anyhow::Result<TargetOutcome> {
        let libraries = self.libraries().await.context("failed to get libraries")?;
        let idle_timeout = std::time::Duration::from_secs(self.idle_timeout);
        let scan_timeout = std::time::Duration::from_secs(self.scan_timeout);

        // library key -> (library, folder -> [(event id, path)]), keeping
        // first-seen order so earlier imports are confirmed first.
        let mut plan: Vec<LibraryPlan> = vec![];
        let mut notes: HashMap<String, String> = HashMap::new();

        for ev in evs {
            let ev_path = ev.get_path(&self.rewrite);
            let matched = self.get_libraries(&libraries, &ev_path);

            if matched.is_empty() {
                error!("no matching library for {ev_path}");
                notes.insert(ev.id.clone(), format!("no Plex library contains {ev_path}"));
                continue;
            }

            let directory = scan_directory(&ev_path).to_string();

            for library in matched {
                let index = match plan.iter().position(|(l, _)| l.key == library.key) {
                    Some(index) => index,
                    None => {
                        plan.push((library, vec![]));
                        plan.len() - 1
                    }
                };
                let folders = &mut plan[index].1;
                let folder = match folders.iter().position(|(d, _)| *d == directory) {
                    Some(index) => index,
                    None => {
                        folders.push((directory.clone(), vec![]));
                        folders.len() - 1
                    }
                };
                folders[folder].1.push((ev.id.clone(), ev_path.clone()));
            }
        }

        let mut verified: HashSet<String> = HashSet::new();
        // Present but in a library type that cannot be looked up by file.
        let mut unverifiable: HashSet<String> = HashSet::new();
        let mut items: HashMap<String, Vec<Metadata>> = HashMap::new();

        for (library, folders) in &plan {
            let mut scanned_any = false;

            for (directory, files) in folders {
                if files.iter().all(|(id, _)| verified.contains(id)) {
                    continue;
                }

                if !self.wait_until_idle(&library.key, idle_timeout).await? {
                    warn!(
                        "'{}' still scanning after {}s, not scanning '{directory}'",
                        library.title, self.idle_timeout
                    );
                    for (id, _) in files {
                        notes.insert(
                            id.clone(),
                            format!(
                                "'{}' was still scanning after {}s, so the scan was not sent",
                                library.title, self.idle_timeout
                            ),
                        );
                    }
                    continue;
                }

                if let Err(e) = self.scan_folder(library, directory).await {
                    error!("failed to scan '{directory}': {e}");
                    for (id, _) in files {
                        notes.insert(id.clone(), format!("scan request failed: {e}"));
                    }
                    continue;
                }
                scanned_any = true;

                let finished = self.wait_for_scan(&library.key, scan_timeout).await?;
                if !finished {
                    warn!(
                        "'{}' still scanning '{directory}' after {}s, checking files anyway",
                        library.title, self.scan_timeout
                    );
                }

                for (id, path) in files {
                    if verified.contains(id) {
                        continue;
                    }

                    match self.find_by_file(library, path).await {
                        Ok(Some(found)) if !found.is_empty() => {
                            debug!("verified '{path}' in '{}'", library.title);
                            verified.insert(id.clone());
                            notes.remove(id);
                            items.entry(id.clone()).or_default().extend(found);
                        }
                        Ok(Some(_)) => {
                            let note = if finished {
                                format!("not in '{}' after the scan finished", library.title)
                            } else {
                                format!(
                                    "not in '{}'; scan still running after {}s",
                                    library.title, self.scan_timeout
                                )
                            };
                            notes.entry(id.clone()).or_insert(note);
                        }
                        Ok(None) => {
                            unverifiable.insert(id.clone());
                        }
                        Err(e) => {
                            notes
                                .entry(id.clone())
                                .or_insert_with(|| format!("library lookup failed: {e:#}"));
                        }
                    }
                }
            }

            if self.empty_trash && scanned_any {
                if let Err(e) = self.empty_trash_now(&library.key).await {
                    error!(
                        "failed to empty trash for library '{}': {e:#}",
                        library.title
                    );
                }
            }
        }

        let mut outcome = TargetOutcome::default();

        for ev in evs {
            if verified.contains(&ev.id) {
                outcome.verified.push(ev.id.clone());
            } else if !unverifiable.contains(&ev.id) {
                if let Some(note) = notes.remove(&ev.id) {
                    outcome.notes.insert(ev.id.clone(), note);
                }
                continue;
            }

            if let Some(found) = items.get(&ev.id) {
                if let Some(note) = self.refresh_and_analyze(found).await {
                    outcome.notes.insert(ev.id.clone(), note);
                    continue;
                }
            }

            outcome.succeeded.push(ev.id.clone());
        }

        Ok(outcome)
    }

    /// Every library on the server with its scan state.
    pub async fn library_states(&self) -> anyhow::Result<Vec<LibraryState>> {
        Ok(self
            .libraries()
            .await?
            .into_iter()
            .map(|library| LibraryState {
                title: library.title,
                kind: library.kind,
                refreshing: library.refreshing,
            })
            .collect())
    }

    pub async fn process_outcome(&self, evs: &[&ScanEvent]) -> anyhow::Result<TargetOutcome> {
        if self.verify {
            self.process_verified(evs).await
        } else {
            self.process(evs).await.map(TargetOutcome::from_succeeded)
        }
    }

    async fn empty_library_trash(
        &self,
        key: &str,
        scanned_at: Option<u64>,
    ) -> anyhow::Result<bool> {
        let scan_finished = tokio::time::timeout(std::time::Duration::from_secs(300), async {
            let started_at = tokio::time::Instant::now();
            let mut observed_scan = false;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let library = self
                    .libraries()
                    .await?
                    .into_iter()
                    .find(|library| library.key == key)
                    .context("scanned library no longer exists")?;
                match library.refreshing {
                    Some(true) => observed_scan = true,
                    Some(false) => {
                        // Idle alone can mean queued. A newer timestamp also catches
                        // short scans that start and finish between polls.
                        let scan_finished = scanned_at
                            .zip(library.scanned_at)
                            .is_some_and(|(before, after)| after > before);
                        if observed_scan || scan_finished {
                            return Ok::<_, anyhow::Error>(true);
                        }
                    }
                    None => anyhow::bail!("Plex did not report the library scan status"),
                }
                if !observed_scan && started_at.elapsed() >= std::time::Duration::from_secs(5) {
                    return Ok(false);
                }
            }
        })
        .await
        .context("timed out waiting for Plex library scan to finish")??;

        if !scan_finished {
            return Ok(false);
        }

        let client = self.get_client()?;
        let url = get_url(&self.url)?.join(&format!("library/sections/{key}/emptyTrash"))?;
        client.put(url).perform().await.map(|_| true)
    }
}

impl TargetProcess for Plex {
    async fn process(&self, evs: &[&ScanEvent]) -> anyhow::Result<Vec<String>> {
        let libraries = self.libraries().await.context("failed to get libraries")?;

        let mut succeeded: HashMap<String, bool> = HashMap::new();
        let mut cleanups: HashMap<String, LibraryCleanup> = HashMap::new();

        for ev in evs {
            let succeeded_entry = succeeded.entry(ev.id.clone()).or_insert(true);

            let ev_path = ev.get_path(&self.rewrite);
            let matched_libraries = self.get_libraries(&libraries, &ev_path);

            if matched_libraries.is_empty() {
                error!("no matching library for {ev_path}");

                *succeeded_entry = false;

                continue;
            }

            let mut processed_items = HashSet::new();

            for library in matched_libraries {
                trace!("found library '{}' for {ev_path}", library.title);

                let scan_result = self.scan(ev, &library).await;
                if self.empty_trash {
                    let cleanup =
                        cleanups
                            .entry(library.key.clone())
                            .or_insert_with(|| LibraryCleanup {
                                scanned_at: library.scanned_at,
                                event_ids: HashSet::new(),
                                scan_failed: false,
                            });
                    cleanup.event_ids.insert(ev.id.clone());
                    cleanup.scan_failed |= scan_result.is_err();
                }

                match scan_result {
                    Ok(()) => {
                        debug!("scanned '{}'", ev_path);

                        if self.analyze || self.refresh {
                            match self.search_items(&library, &ev_path).await {
                                Ok(items) => {
                                    if items.is_empty() {
                                        trace!(
                                            "failed to find items for file: '{}', leaving at scan",
                                            ev_path
                                        );

                                        // scan succeeded, no items to refresh/analyze
                                    } else {
                                        trace!("found items for file '{}'", ev_path);

                                        let mut all_success = true;

                                        for item in items {
                                            let mut item_success = true;

                                            if processed_items.contains(&item.key) {
                                                debug!(
                                                    "already processed item '{}' earlier, skipping",
                                                    item.key
                                                );
                                                continue;
                                            }

                                            if self.refresh {
                                                match self.refresh_item(&item.key).await {
                                                    Ok(()) => {
                                                        debug!("refreshed metadata '{}'", item.key);
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                        "failed to refresh metadata for '{}': {}",
                                                        item.key, e
                                                    );
                                                        item_success = false;
                                                    }
                                                }
                                            }

                                            if self.analyze {
                                                match self.analyze_item(&item.key).await {
                                                    Ok(()) => {
                                                        debug!("analyzed metadata '{}'", item.key);
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                        "failed to analyze metadata for '{}': {}",
                                                        item.key, e
                                                    );
                                                        item_success = false;
                                                    }
                                                }
                                            }

                                            if !item_success {
                                                all_success = false;
                                            }

                                            processed_items.insert(item.key);
                                        }

                                        if !all_success {
                                            *succeeded_entry = false;
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("failed to get items for '{}': {:?}", ev_path, e);
                                    *succeeded_entry = false;
                                }
                            };
                        }
                    }
                    Err(e) => {
                        error!("failed to scan file '{}': {}", ev_path, e);
                        *succeeded_entry = false;
                    }
                }
            }
        }

        for (key, cleanup) in cleanups {
            let result = if cleanup.scan_failed {
                Err(anyhow::anyhow!("a scan failed for this library"))
            } else {
                self.empty_library_trash(&key, cleanup.scanned_at).await
            };

            match result {
                Ok(true) => debug!("emptied trash for library '{key}'"),
                Ok(false) => warn!("skipped trash for library '{key}': Plex did not report a scan"),
                Err(e) => {
                    error!("failed to empty trash for library '{key}': {e:#}");
                    for id in cleanup.event_ids {
                        succeeded.insert(id, false);
                    }
                }
            }
        }

        Ok(succeeded
            .into_iter()
            .filter_map(|(k, v)| if v { Some(k) } else { None })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_plex() -> Plex {
        Plex {
            url: String::new(),
            token: String::new(),
            refresh: false,
            analyze: false,
            empty_trash: false,
            rewrite: None,
            filter: PathFilter::default(),
            request: Request::default(),
            verify: false,
            idle_timeout: default_idle_timeout(),
            scan_timeout: default_scan_timeout(),
        }
    }

    #[test]
    fn test_get_search_term() {
        let plex = test_plex();

        // Test with a path that has a file name and season directory
        let path = "/media/TV Shows/Breaking Bad/Season 1/S01E01.mkv";
        assert_eq!(plex.get_search_term(path).unwrap(), "Breaking Bad");

        // Test with a path that has parentheses and brackets
        let path = "/media/Movies/The Matrix (1999) [1080p]/matrix.mkv";
        assert_eq!(plex.get_search_term(path).unwrap(), "The Matrix");

        // Test with a simple path
        let path = "/media/Movies/Inception/inception.mkv";
        assert_eq!(plex.get_search_term(path).unwrap(), "Inception");

        // Test with a directory path
        let path = "/media/TV Shows/Game of Thrones/Season 2";
        assert_eq!(plex.get_search_term(path).unwrap(), "Game of Thrones");

        // Test with no directory path
        let path = "/media/TV Shows/Game of Thrones";
        assert_eq!(plex.get_search_term(path).unwrap(), "Game of Thrones");

        // Test with multiple levels of season directories
        let path = "/media/TV Shows/Doctor Who/Season 10/Season 10 Part 2/S10E12.mkv";
        assert_eq!(plex.get_search_term(path).unwrap(), "Doctor Who");
    }

    #[test]
    fn test_get_library() {
        let plex = Plex {
            url: String::new(),
            token: String::new(),
            refresh: false,
            analyze: false,
            empty_trash: false,
            rewrite: None,
            filter: PathFilter::default(),
            request: Request::default(),
            verify: false,
            idle_timeout: default_idle_timeout(),
            scan_timeout: default_scan_timeout(),
        };

        let libraries = [Library {
            title: "Movies".to_string(),
            key: "library_key_movies".to_string(),
            kind: None,
            refreshing: None,
            scanned_at: None,
            location: vec![Location {
                path: "/media/movies".to_string(),
            }],
        }];

        let path = "/media/movies/Inception.mkv";
        let libraries = plex.get_libraries(&libraries, path);
        assert!(libraries[0].key == "library_key_movies");

        let nested_libraries = [
            Library {
                title: "Movies".to_string(),
                key: "library_key_movies".to_string(),
                kind: None,
                refreshing: None,
                scanned_at: None,
                location: vec![Location {
                    path: "/media/movies".to_string(),
                }],
            },
            Library {
                title: "Movies".to_string(),
                key: "library_key_movies_4k".to_string(),
                kind: None,
                refreshing: None,
                scanned_at: None,
                location: vec![Location {
                    path: "/media/movies/4k".to_string(),
                }],
            },
        ];

        let path = "/media/movies/4k/Inception.mkv";

        let libraries = plex.get_libraries(&nested_libraries, path);
        assert!(libraries[0].key == "library_key_movies_4k");
        assert!(libraries[1].key == "library_key_movies");
    }

    #[test]
    fn windows_library_matching_prefers_the_most_specific_location() {
        let libraries = [
            Library {
                title: "Movies".to_string(),
                key: "movies".to_string(),
                kind: None,
                refreshing: None,
                scanned_at: None,
                location: vec![Location {
                    path: r"\\server\media".to_string(),
                }],
            },
            Library {
                title: "4K Movies".to_string(),
                key: "movies-4k".to_string(),
                kind: None,
                refreshing: None,
                scanned_at: None,
                location: vec![Location {
                    path: r"\\SERVER\MEDIA\4K".to_string(),
                }],
            },
        ];

        let matches = test_plex().get_libraries(&libraries, r"\\server\media\4k\Film\Film.mkv");

        assert_eq!(
            matches
                .iter()
                .map(|library| library.key.as_str())
                .collect::<Vec<_>>(),
            ["movies-4k", "movies"]
        );
    }

    #[test]
    fn unc_file_produces_a_non_empty_scan_directory_in_original_syntax() {
        assert_eq!(
            scan_directory(r"\\server\media\TV\Show\Season 1\S01E01.mkv"),
            r"\\server\media\TV\Show\Season 1"
        );
    }

    #[test]
    fn windows_search_term_skips_season_components() {
        assert_eq!(
            test_plex()
                .get_search_term(r"D:\TV Shows\Breaking Bad\Season 1\S01E01.mkv")
                .unwrap(),
            "Breaking Bad"
        );
    }

    #[test]
    fn windows_media_matching_uses_runtime_case_and_boundaries() {
        assert!(path_matches(
            r"D:\MEDIA\Movies\Film\Film.mkv",
            r"d:\media\movies\film\film.MKV"
        ));
        assert!(path_matches(
            r"\\server\media\Shows\Show\Episode.mkv",
            r"\\SERVER\MEDIA\SHOWS\SHOW"
        ));
        assert!(!path_matches(
            r"\\server\media-archive\Film.mkv",
            r"\\server\media"
        ));
    }

    #[test]
    fn unix_search_term_without_a_non_season_parent_uses_the_directory_name() {
        assert_eq!(
            test_plex().get_search_term("/Season 1/file.mkv").unwrap(),
            "Season 1"
        );
    }

    #[test]
    fn windows_search_term_without_a_non_season_parent_uses_the_directory_name() {
        assert_eq!(
            test_plex()
                .get_search_term(r"D:\Season 1\S01E01.mkv")
                .unwrap(),
            "Season 1"
        );

        // Same fallback, but called directly on the Season directory rather
        // than a file within it: `parent_or_self` takes its other branch
        // (`is_file()` is false, so the source is used unchanged) and must
        // still resolve to the directory name.
        assert_eq!(
            test_plex().get_search_term(r"D:\Season 1").unwrap(),
            "Season 1"
        );
    }
}
