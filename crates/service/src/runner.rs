use crate::manager::PulseManager;
use crate::settings::webhooks::EventType;
use autopulse_database::{
    diesel::{
        self, BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper,
    },
    models::{FoundStatus, ProcessStatus, ScanEvent},
    schema::scan_events::{
        can_process, created_at, dsl::scan_events, found_status, next_retry_at, process_status,
    },
};
use autopulse_utils::sha256checksum;
use autopulse_utils::sify;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tracing::{debug, error, info, info_span, warn, Instrument};

/// Seconds to wait before retrying an event that has failed `failed_times`
/// times: doubles after each failure, optionally capped by
/// [`opts.max_retry_delay`](crate::settings::opts::Opts::max_retry_delay).
fn retry_delay(failed_times: i32, max_retry_delay: Option<u64>) -> i64 {
    // A year is far beyond any useful retry and keeps chrono in range.
    const CEILING: i64 = 365 * 24 * 60 * 60;

    let exponent = u32::try_from(failed_times.saturating_add(1)).unwrap_or(0);
    let delay = 2_i64.checked_pow(exponent).unwrap_or(CEILING).min(CEILING);

    match max_retry_delay {
        Some(max) => delay.min(i64::try_from(max).unwrap_or(CEILING)),
        None => delay,
    }
}

enum FileCheckResult {
    NotFound,
    Found,
    HashMatch,
    HashMismatch,
}

pub(super) struct PulseRunner<'a> {
    manager: &'a PulseManager,
    anchors_available: bool,
}

impl<'a> PulseRunner<'a> {
    pub fn new(manager: &'a PulseManager) -> Self {
        Self {
            manager,
            anchors_available: true,
        }
    }

    async fn update_found_status(&self) -> anyhow::Result<()> {
        if !self.manager.settings.opts.check_path {
            return Ok(());
        }

        let mut found_files: Vec<(String, String)> = vec![];
        let mut mismatched_files: Vec<(String, String)> = vec![];

        let evs = self
            .manager
            .database(|conn| {
                Ok(scan_events
                    .filter(found_status.ne::<String>(FoundStatus::Found.into()))
                    .filter(process_status.eq::<String>(ProcessStatus::Pending.into()))
                    .select(ScanEvent::as_select())
                    .load(conn)?)
            })
            .await?;

        for ev in evs {
            let file_path = PathBuf::from(&ev.file_path);

            let expected_hash = ev.file_hash.clone();
            let result: FileCheckResult =
                tokio::task::spawn_blocking(move || -> anyhow::Result<FileCheckResult> {
                    if !file_path.exists() {
                        return Ok(FileCheckResult::NotFound);
                    }
                    match expected_hash {
                        Some(hash) => {
                            let file_hash = sha256checksum(&file_path)?;
                            if hash == file_hash {
                                Ok(FileCheckResult::HashMatch)
                            } else {
                                Ok(FileCheckResult::HashMismatch)
                            }
                        }
                        None => Ok(FileCheckResult::Found),
                    }
                })
                .await
                .map_err(|e| anyhow::anyhow!("file check task failed: {e}"))??;

            let (status, bus_kind) = match result {
                FileCheckResult::NotFound => {
                    // Nothing transitioned; skip the write so we don't
                    // churn `updated_at` (and UI ordering) every poll.
                    continue;
                }
                FileCheckResult::Found | FileCheckResult::HashMatch => {
                    // The outer query filters out rows already in Found,
                    // so reaching this arm is always a real transition.
                    (FoundStatus::Found, EventType::Found)
                }
                FileCheckResult::HashMismatch => {
                    // Only persist on the *first* time we see a mismatch.
                    // Re-polls of an already-mismatched row must not
                    // clobber the original `found_at` or churn the row.
                    if ev.found_status == FoundStatus::HashMismatch.to_string() {
                        continue;
                    }
                    (FoundStatus::HashMismatch, EventType::HashMismatch)
                }
            };

            let status = status.to_string();
            let at = chrono::Utc::now().naive_utc();
            let Some(saved) = self
                .manager
                .database(move |conn| conn.update_found(&ev, &status, at))
                .await?
            else {
                continue;
            };
            match bus_kind {
                EventType::Found => {
                    found_files.push((saved.file_path.clone(), saved.event_source.clone()))
                }
                EventType::HashMismatch => {
                    mismatched_files.push((saved.file_path.clone(), saved.event_source.clone()))
                }
                _ => unreachable!(),
            }
            self.manager.publish(bus_kind, &saved);
        }

        if !found_files.is_empty() {
            info!("found {} new file{}", found_files.len(), sify(&found_files));

            for (file, trigger) in found_files {
                debug!("file '{file}' found from '{trigger}'");

                self.manager
                    .webhooks
                    .add_event(EventType::Found, Some(trigger), &[file])
                    .await;
            }
        }

        if !mismatched_files.is_empty() {
            warn!(
                "found {} mismatched file{}",
                mismatched_files.len(),
                sify(&mismatched_files)
            );

            for (file, trigger) in &mismatched_files {
                debug!("file '{file}' hash mismatch from '{trigger}'");

                self.manager
                    .webhooks
                    .add_event(
                        EventType::HashMismatch,
                        Some(trigger.clone()),
                        std::slice::from_ref(file),
                    )
                    .await;
            }
        }

        Ok(())
    }

    pub async fn update_process_status(&self) -> anyhow::Result<()> {
        let check_path = self.manager.settings.opts.check_path;
        let mut evs = self
            .manager
            .database(move |conn| {
                let base_query = scan_events
                    .limit(100)
                    .filter(process_status.eq_any([
                        String::from(ProcessStatus::Pending),
                        String::from(ProcessStatus::Retry),
                    ]))
                    .filter(
                        next_retry_at
                            .is_null()
                            .or(next_retry_at.lt(chrono::Utc::now().naive_utc())),
                    )
                    // filter by processable events
                    .filter(can_process.lt(chrono::Utc::now().naive_utc()));

                let evs = if check_path {
                    base_query
                        .filter(found_status.eq::<String>(FoundStatus::Found.into()))
                        .select(ScanEvent::as_select())
                        .load(conn)?
                } else {
                    base_query.select(ScanEvent::as_select()).load(conn)?
                };
                Ok(evs)
            })
            .await?;

        if evs.is_empty() {
            return Ok(());
        }

        let (processed, retrying, failed) = self.process_events(&mut evs).await?;

        if !processed.is_empty() {
            info!(
                "sent {} file{} to targets",
                processed.len(),
                sify(&processed)
            );

            for ev in &processed {
                debug!(
                    "processed file '{}' from '{}'",
                    ev.file_path, ev.event_source
                );

                self.manager
                    .webhooks
                    .add_event(
                        EventType::Processed,
                        Some(ev.event_source.clone()),
                        std::slice::from_ref(&ev.file_path),
                    )
                    .await;
                self.manager.publish(EventType::Processed, ev);
            }
        }

        if !retrying.is_empty() {
            warn!("retrying {} file{}", retrying.len(), sify(&retrying));

            for ev in &retrying {
                debug!(
                    "retrying file '{}' from '{}'",
                    ev.file_path, ev.event_source
                );

                self.manager
                    .webhooks
                    .add_event(
                        EventType::Retrying,
                        Some(ev.event_source.clone()),
                        std::slice::from_ref(&ev.file_path),
                    )
                    .await;
                self.manager.publish(EventType::Retrying, ev);
            }
        }

        if !failed.is_empty() {
            error!(
                "failed to send {} file{} to targets",
                failed.len(),
                sify(&failed)
            );

            for ev in &failed {
                debug!("failed file '{}' from '{}'", ev.file_path, ev.event_source);

                self.manager
                    .webhooks
                    .add_event(
                        EventType::Failed,
                        Some(ev.event_source.clone()),
                        std::slice::from_ref(&ev.file_path),
                    )
                    .await;
                self.manager.publish(EventType::Failed, ev);
            }
        }

        Ok(())
    }

    async fn process_events(
        &self,
        evs: &mut [ScanEvent],
    ) -> anyhow::Result<(Vec<ScanEvent>, Vec<ScanEvent>, Vec<ScanEvent>)> {
        let previous = evs.to_vec();
        let mut failed_ids = vec![];
        let mut verified_ids = HashSet::new();
        // Why each failed event failed, for the UI and retry decisions.
        let mut notes: HashMap<String, String> = HashMap::new();

        let trigger_settings = &self.manager.settings.triggers;

        for (name, target) in &self.manager.settings.targets {
            let evs = evs
                .iter_mut()
                .filter(|x| !x.get_targets_hit().contains(name))
                .filter(|x| {
                    trigger_settings
                        .get(&x.event_source)
                        .is_none_or(|trigger| !trigger.excludes().contains(name))
                })
                .filter(|x| target.should_process_event(x))
                .collect::<Vec<&mut ScanEvent>>();

            if evs.is_empty() {
                continue;
            }

            let res = target
                .process_outcome(
                    // TODO: Somehow clean this up
                    evs.iter()
                        .map(|x| &**x)
                        .collect::<Vec<&ScanEvent>>()
                        .as_slice(),
                )
                .instrument(info_span!("process ", target = name))
                .await;

            match res {
                Ok(outcome) => {
                    for ev in evs {
                        if outcome.verified.contains(&ev.id) {
                            verified_ids.insert(ev.id.clone());
                        }

                        if outcome.succeeded.contains(&ev.id) {
                            ev.add_target_hit(name);
                        } else {
                            failed_ids.push(ev.id.clone());

                            let note = outcome
                                .notes
                                .get(&ev.id)
                                .map_or("did not report success", String::as_str);
                            notes.insert(ev.id.clone(), format!("{name}: {note}"));
                        }
                    }
                }
                Err(e) => {
                    for ev in &evs {
                        failed_ids.push(ev.id.clone());
                        notes.insert(ev.id.clone(), format!("{name}: {e:#}"));
                    }

                    error!("failed to process target '{}': {:?}", name, e);
                }
            }
        }

        let mut succeeded = vec![];
        let mut retrying = vec![];
        let mut failed = vec![];

        for (ev, previous) in evs.iter_mut().zip(previous) {
            ev.updated_at = chrono::Utc::now().naive_utc();

            if verified_ids.contains(&ev.id) && ev.verified_at.is_none() {
                ev.verified_at = Some(ev.updated_at);
            }

            if let Some(note) = notes.remove(&ev.id) {
                ev.last_error = Some(note);
            }

            if failed_ids.contains(&ev.id) {
                ev.failed_times += 1;

                if ev.failed_times >= self.manager.settings.opts.max_retries {
                    ev.process_status = ProcessStatus::Failed.into();
                    ev.next_retry_at = None;
                } else {
                    let next_retry = chrono::Utc::now().naive_utc()
                        + chrono::Duration::seconds(retry_delay(
                            ev.failed_times,
                            self.manager.settings.opts.max_retry_delay,
                        ));

                    ev.process_status = ProcessStatus::Retry.into();
                    ev.next_retry_at = Some(next_retry);
                }
            } else {
                ev.process_status = ProcessStatus::Complete.into();
                ev.next_retry_at = None;
                ev.processed_at = Some(chrono::Utc::now().naive_utc());
            }
            let updated = ev.clone();
            let Some(saved) = self
                .manager
                .database(move |conn| conn.update_process(&previous, &updated))
                .await?
            else {
                continue;
            };
            match saved.process_status.as_str() {
                "complete" => succeeded.push(saved),
                "retry" => retrying.push(saved),
                "failed" => failed.push(saved),
                _ => unreachable!(),
            }
        }

        Ok((succeeded, retrying, failed))
    }

    async fn cleanup(&self) -> anyhow::Result<()> {
        let time_before_cleanup = chrono::Utc::now().naive_utc()
            - chrono::Duration::days(self.manager.settings.opts.cleanup_days as i64);

        self.manager
            .database(move |conn| {
                let delete_old_events = diesel::delete(
                    scan_events
                        .filter(
                            (found_status.eq::<String>(FoundStatus::NotFound.into()))
                                .or(process_status.eq::<String>(ProcessStatus::Failed.into())),
                        )
                        .filter(created_at.lt(time_before_cleanup)),
                );

                if let Err(e) = delete_old_events.execute(conn) {
                    error!("failed to delete old events: {:?}", e);
                }

                Ok(())
            })
            .await
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let set_anchors_available = self
            .manager
            .settings
            .anchors
            .iter()
            .all(|anchor| anchor.exists());

        if set_anchors_available != self.anchors_available {
            if set_anchors_available {
                info!("anchors are available again, continuing");
            } else {
                warn!("anchors are not available, pausing");
            }
            self.anchors_available = set_anchors_available;
        }

        if !self.anchors_available {
            return Ok(());
        }

        self.update_found_status().await?;
        self.update_process_status().await?;
        self.cleanup().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::retry_delay;

    #[test]
    fn retry_delay_doubles_after_each_failure() {
        assert_eq!(retry_delay(1, None), 4);
        assert_eq!(retry_delay(2, None), 8);
        assert_eq!(retry_delay(3, None), 16);
    }

    #[test]
    fn retry_delay_respects_the_configured_cap() {
        assert_eq!(retry_delay(3, Some(10)), 10);
        assert_eq!(retry_delay(1, Some(10)), 4);
    }

    #[test]
    fn retry_delay_does_not_overflow_on_many_failures() {
        assert_eq!(retry_delay(100, None), 365 * 24 * 60 * 60);
        assert_eq!(retry_delay(i32::MAX, Some(600)), 600);
    }
}
