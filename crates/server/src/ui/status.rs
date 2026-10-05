//! Live view of what targets are doing: Plex library scan states and the
//! events still being retried, refreshed every few seconds.

use actix_web::{error::ErrorInternalServerError, get, web::Data, HttpRequest, Result};
use autopulse_database::models::ScanEvent;
use autopulse_service::{
    manager::PulseManager,
    settings::targets::{plex::Plex, Target},
};
use maud::{html, Markup};

use crate::ui::{
    auth::{ctx, SessionUser},
    csrf::CsrfToken,
    events_view::truncate,
    layout,
};

/// Rows shown per event list on the page.
const LIST_SIZE: u8 = 25;

#[get("/ui/status")]
pub async fn status_page(
    manager: Data<PulseManager>,
    _user: SessionUser,
    csrf: CsrfToken,
    req: HttpRequest,
) -> Result<Markup> {
    let section = status_section(&manager).await?;
    if req.headers().contains_key("HX-Request") {
        Ok(section)
    } else {
        let ctx = ctx(&manager, &csrf.0);
        Ok(layout::page(&ctx, "status", "status", section))
    }
}

async fn status_section(manager: &PulseManager) -> Result<Markup> {
    let base = manager.settings.app.base_path.as_str();
    let stats = manager
        .get_stats()
        .await
        .map_err(ErrorInternalServerError)?;
    let retrying = manager
        .get_events(
            LIST_SIZE,
            1,
            Some("updated_at".into()),
            Some("retry".into()),
            None,
        )
        .await
        .map_err(ErrorInternalServerError)?;
    let failed = manager
        .get_events(
            LIST_SIZE,
            1,
            Some("updated_at".into()),
            Some("failed".into()),
            None,
        )
        .await
        .map_err(ErrorInternalServerError)?;

    let mut targets = manager.settings.targets.iter().collect::<Vec<_>>();
    targets.sort_by(|a, b| a.0.cmp(b.0));

    let mut plex_panels = vec![];
    for (name, target) in targets {
        if let Target::Plex(plex) = target {
            plex_panels.push(plex_panel(name, plex).await);
        }
    }

    Ok(html! {
        section.status #status-section
            hx-get={ (base) "/ui/status" }
            hx-trigger="every 5s"
            hx-swap="outerHTML"
        {
            header.page-head {
                h1.page-title { "Status" }
                span.page-meta { "refreshes every 5s" }
            }

            .status-grid {
                .panel {
                    .panel__head { "Verification" }
                    .panel__body {
                        dl.status-counts {
                            (count("Confirmed in library", stats.verified, "complete"))
                            (count("Being retried", stats.retrying, "retry"))
                            (count("Gave up", stats.failed, "failed"))
                            (count("Waiting", stats.pending, "pending"))
                        }
                    }
                }

                @for panel in &plex_panels { (panel) }
            }

            (event_panel(base, "Being retried", "Nothing is waiting on a retry.", &retrying))
            (event_panel(base, "Gave up", "Nothing has run out of retries.", &failed))
        }
    })
}

fn count(label: &str, value: i64, kind: &str) -> Markup {
    html! {
        .status-count {
            dt.status-count__label { (label) }
            dd.status-count__value .{ "status-count__value--" (kind) } data-num=(value) { (value) }
        }
    }
}

async fn plex_panel(name: &str, plex: &Plex) -> Markup {
    let libraries = plex.library_states().await;

    html! {
        .panel {
            .panel__head {
                (name) " \u{00b7} Plex"
                @if plex.verify {
                    span.status-tag.status-tag--on { "verifying" }
                } @else {
                    span.status-tag { "not verifying" }
                }
            }
            .panel__body {
                @match libraries {
                    Ok(libraries) => {
                        ul.status-libraries {
                            @for library in libraries {
                                li.status-library {
                                    span.status-library__name { (library.title) }
                                    @match library.refreshing {
                                        Some(true) => span.badge.badge--retry { "scanning" },
                                        Some(false) => span.badge.badge--complete { "idle" },
                                        None => span.badge { "unknown" },
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        p.status-error { "Could not reach Plex: " (format!("{e:#}")) }
                    }
                }
            }
        }
    }
}

fn event_panel(base: &str, title: &str, empty: &str, events: &[ScanEvent]) -> Markup {
    html! {
        .panel.status-events {
            .panel__head { (title) " (" (events.len()) @if events.len() == usize::from(LIST_SIZE) { "+" } ")" }
            .panel__body.panel__body--flush {
                @if events.is_empty() {
                    p.status-empty { (empty) }
                } @else {
                    table.events__table {
                        thead { tr {
                            th { "Path" } th { "Tries" } th { "Last issue" } th { "Next try" }
                        } }
                        tbody {
                            @for ev in events {
                                tr {
                                    td.cell--path title=(ev.file_path) {
                                        a.cell--path__link href={ (base) "/ui/events/" (ev.id) } { (ev.file_path) }
                                    }
                                    td { (ev.failed_times) }
                                    td.cell--failure title=[ev.last_error.as_deref()] {
                                        (ev.last_error.as_deref().map_or_else(|| "\u{2014}".to_string(), |e| truncate(e, 90)))
                                    }
                                    td.cell--ts {
                                        @match ev.next_retry_at {
                                            Some(at) => time.local-ts datetime=(at.format("%Y-%m-%dT%H:%M:%SZ")) {
                                                (at.format("%Y-%m-%d %H:%M:%S"))
                                            },
                                            None => span.dim { "\u{2014}" },
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
