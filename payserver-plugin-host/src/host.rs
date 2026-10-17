//! Runs plugins: dispatches actions and filters, bounds every call with a
//! deadline, and disables a plugin after repeated failure — with the reason
//! visible without going anywhere near wasmtime.
//!
//! # Action vs. filter
//!
//! These are two different entry points, not one dispatch call with a flag,
//! because they fail differently:
//!
//! - [`PluginHost::run_action`] is fire-and-forget. It returns nothing, so
//!   there is nothing for a failing action to change; failure is only ever
//!   observable via [`PluginHost::status`].
//! - [`PluginHost::run_filter`] carries the call's deadline and, when the
//!   filter cannot run, resolves to the manifest's declared
//!   [`FailureMode`] — closed unless the manifest said otherwise, per
//!   [`payserver_plugin_api::Manifest`]'s own parse-time default.
//!
//! Neither of these is wired to anything that touches payment detection,
//! crediting or confirmation, and nothing in this module could be: the only
//! hook points that exist are the generic `run_action`/`run_filter` calls
//! above, keyed by a plugin-supplied export name chosen by whoever adds the
//! next call site. The money-path hook points this must never become
//! belong to a future, host-API-surface ticket — this slice adds no hook
//! points of its own at all.
//!
//! # Why the admin surface survives a crash loop
//!
//! [`PluginHost::status`] never touches the [`std::sync::Mutex`] guarding a
//! plugin's wasmtime instance. It reads two atomics and, at most, a small
//! `RwLock<String>` holding the disabled reason — none of which a stuck or
//! looping call ever holds while blocked inside wasm. And once a plugin is
//! disabled, `run_action`/`run_filter` stop calling into wasmtime for it at
//! all, so a crash loop is bounded to `max_failures` attempts, not
//! unbounded.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, TryLockError};
use std::time::{Duration, Instant};

use payserver_plugin_api::{FailureMode, Manifest, PluginId, PluginKind, Version};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::PluginLoadError;
use super::registry::PluginRegistry;
use super::runtime::PluginHostCalls;
use super::runtime::{PluginCallError, PluginEngine, PluginInstance, PluginWasmError};

/// A plugin failed either the load-time gate or wasm compilation /
/// instantiation.
#[derive(Debug, thiserror::Error)]
pub enum PluginHostError {
    #[error(transparent)]
    Rejected(#[from] PluginLoadError),
    #[error(transparent)]
    Wasm(#[from] PluginWasmError),
}

/// What happened when a filter could not be run to completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterOutcome<T> {
    /// The filter ran and answered.
    Ran(T),
    /// The filter could not run — missing, disabled, trapped, timed out, or
    /// its answer didn't parse. `allowed` is the manifest's
    /// [`FailureMode`] applied: `true` for [`FailureMode::Open`], `false`
    /// for [`FailureMode::Closed`] (the default for a filter that declares
    /// nothing). `reason` is always populated, for the admin's benefit.
    CouldNotRun { allowed: bool, reason: String },
}

impl<T> FilterOutcome<T> {
    fn could_not_run(failure_mode: FailureMode, reason: impl Into<String>) -> Self {
        Self::CouldNotRun {
            allowed: matches!(failure_mode, FailureMode::Open),
            reason: reason.into(),
        }
    }
}

/// A point-in-time read of one plugin's health, safe to expose on an admin
/// page regardless of what the plugin itself is doing right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginStatusSnapshot {
    pub id: PluginId,
    pub enabled: bool,
    pub disabled_reason: Option<String>,
    pub consecutive_failures: u32,
}

enum EntryStatus {
    Enabled,
    Disabled { reason: String },
}

/// One registered, instantiated plugin plus the bookkeeping needed to
/// disable it and to report on it without touching its execution lock.
///
/// The manifest itself lives in [`PluginRegistry`], not here — this only
/// needs `max_failures`, resolved once at registration time.
struct PluginEntry {
    id: PluginId,
    instance: Mutex<PluginInstance>,
    failures: AtomicU32,
    status: RwLock<EntryStatus>,
    max_failures: u32,
}

impl PluginEntry {
    fn new(id: PluginId, instance: PluginInstance, max_failures: u32) -> Self {
        Self {
            id,
            instance: Mutex::new(instance),
            failures: AtomicU32::new(0),
            status: RwLock::new(EntryStatus::Enabled),
            max_failures,
        }
    }

    fn is_enabled(&self) -> bool {
        matches!(
            *self.status.read().unwrap_or_else(PoisonError::into_inner),
            EntryStatus::Enabled
        )
    }

    /// Records a successful call, resetting the failure streak — an
    /// occasional failure in an otherwise-healthy plugin should not creep
    /// it towards disablement.
    fn record_success(&self) {
        self.failures.store(0, Ordering::SeqCst);
    }

    /// A call that never started because the instance stayed busy with
    /// another call. The call holding it is what failed, and records that
    /// itself; counting every caller queued behind it as well would disable
    /// a healthy plugin because one call was slow.
    fn record_busy(&self) {
        tracing::warn!(
            plugin_id = %self.id,
            "plugin call gave up waiting for the instance: another call holds it past the deadline"
        );
    }

    /// Records a failed call. Once `max_failures` consecutive failures have
    /// been seen, disables the plugin and remembers why — the reason an
    /// admin needs to see to fix it, not just "disabled".
    ///
    /// Every failure is also logged here, not just counted: `status()` is a
    /// pull the admin has to know to make, so it alone does not satisfy
    /// "failures logged" for an action, which has no other observer at all.
    fn record_failure(&self, reason: String) {
        tracing::warn!(plugin_id = %self.id, reason = %reason, "plugin call failed");
        let failures = self.failures.fetch_add(1, Ordering::SeqCst) + 1;
        if failures >= self.max_failures {
            tracing::error!(
                plugin_id = %self.id,
                reason = %reason,
                consecutive_failures = failures,
                "plugin disabled after repeated failure"
            );
            self.disable(reason);
        }
    }

    /// Switch this entry off and record why.
    ///
    /// Shared by the repeated-failure path and by an admin's explicit
    /// disable, so there is one representation of "off" rather than two that
    /// could report differently.
    fn disable(&self, reason: String) {
        *self.status.write().unwrap_or_else(PoisonError::into_inner) =
            EntryStatus::Disabled { reason };
    }

    /// Switch this entry back on and forgive its failure history.
    fn enable(&self) {
        self.failures.store(0, Ordering::SeqCst);
        *self.status.write().unwrap_or_else(PoisonError::into_inner) = EntryStatus::Enabled;
    }

    fn snapshot(&self, id: PluginId) -> PluginStatusSnapshot {
        let consecutive_failures = self.failures.load(Ordering::SeqCst);
        let disabled_reason = match &*self.status.read().unwrap_or_else(PoisonError::into_inner) {
            EntryStatus::Enabled => None,
            EntryStatus::Disabled { reason } => Some(reason.clone()),
        };
        PluginStatusSnapshot {
            id,
            enabled: disabled_reason.is_none(),
            disabled_reason,
            consecutive_failures,
        }
    }
}

/// Loads, runs and bounds plugins.
///
/// One [`PluginEngine`] (and its epoch ticker) is shared across every
/// plugin this host loads; each plugin gets its own instantiated, kept-alive
/// [`PluginInstance`] behind its own call lock, so a slow or stuck plugin
/// never blocks another plugin's calls or a status read.
///
/// The engine is behind an [`Arc`], not owned outright, because
/// [`PluginHost::run_action`] detaches its call onto a background task that
/// can outlive `&self` — without its own strong reference to the engine, a
/// `PluginHost` dropped while an action is still in flight would take the
/// epoch ticker down with it, and a plugin stuck in a loop would then have
/// nothing left to interrupt it: the deadline would never fire.
pub struct PluginHost {
    engine: Arc<PluginEngine>,
    registry: RwLock<PluginRegistry>,
    entries: RwLock<HashMap<PluginId, Arc<PluginEntry>>>,
    max_failures: u32,
    call_deadline: Duration,
}

impl PluginHost {
    pub fn new(host_version: Version, max_failures: u32, call_deadline: Duration) -> Self {
        Self {
            engine: Arc::new(PluginEngine::new()),
            registry: RwLock::new(PluginRegistry::new(host_version)),
            entries: RwLock::new(HashMap::new()),
            max_failures,
            call_deadline,
        }
    }

    #[cfg(test)]
    fn with_tick(
        host_version: Version,
        max_failures: u32,
        call_deadline: Duration,
        tick: Duration,
    ) -> Self {
        Self {
            engine: Arc::new(PluginEngine::with_tick(tick)),
            registry: RwLock::new(PluginRegistry::new(host_version)),
            entries: RwLock::new(HashMap::new()),
            max_failures,
            call_deadline,
        }
    }

    /// Compiles and instantiates `wasm` — once; the resulting instance is
    /// kept and reused across every future call — before touching the
    /// registry at all, so a plugin id is only ever claimed once both have
    /// actually succeeded. Compiling first (rather than validating the
    /// manifest, then compiling, then rolling back on failure) means a bad
    /// manifest and a bad module both leave the id free to retry, with no
    /// partial state to unwind either way.
    pub fn register(&self, manifest: Manifest, wasm: &[u8]) -> Result<(), PluginHostError> {
        self.register_with_calls(manifest, wasm, None)
    }

    /// [`register`](Self::register), with `calls` available to the plugin as
    /// host imports for the life of its instance.
    ///
    /// Separate from `register` rather than an extra argument on it: a host
    /// that offers a plugin no capabilities at all is a legitimate
    /// configuration - and the one every test here uses - so it should not
    /// have to name `None` to say so.
    ///
    /// The calls are bound at instantiation and cannot be changed afterwards.
    /// A plugin is instantiated once and kept for the life of the process, so
    /// swapping them later would mean a plugin holding a stale handle to
    /// whatever it was given first; re-registering is the way to change them.
    ///
    /// # Errors
    /// As [`register`](Self::register).
    pub fn register_with_calls(
        &self,
        manifest: Manifest,
        wasm: &[u8],
        calls: Option<Arc<dyn PluginHostCalls>>,
    ) -> Result<(), PluginHostError> {
        let module = self.engine.compile(wasm)?;
        let instance = match calls {
            Some(calls) => self.engine.instantiate_with_calls(&module, calls)?,
            None => self.engine.instantiate(&module)?,
        };

        let id = manifest.id.clone();
        self.registry
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .register(manifest)?;

        let entry = Arc::new(PluginEntry::new(id.clone(), instance, self.max_failures));
        self.entries
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, entry);
        Ok(())
    }

    /// Stop dispatching to a plugin, now, in this process.
    ///
    /// The install record is what the next boot honours, but an admin
    /// disabling a misbehaving plugin means *stop running it*, not "stop
    /// running it after I restart the server". Without this, the one
    /// recovery path that does not require a restart would not actually
    /// recover anything - the row would say disabled while the plugin kept
    /// being consulted on every request until someone bounced the process.
    ///
    /// Takes the same route a repeated-failure disable takes, so a plugin
    /// switched off by an admin and one switched off by the host are in the
    /// same state and report the same way.
    ///
    /// Returns whether a plugin with that id was loaded at all. `false` is
    /// not an error: a plugin installed but never loaded - safe mode, or a
    /// boot that could not read its artifact - has nothing here to disable,
    /// and the caller still has a row to update.
    ///
    /// Deliberately does not drop the instance. Freeing the wasmtime store
    /// while a detached `run_action` may still be inside it is a different
    /// problem; a disabled entry is never dispatched to again, which is the
    /// property that matters.
    pub fn disable(&self, id: &PluginId, reason: impl Into<String>) -> bool {
        let entries = self.entries.read().unwrap_or_else(PoisonError::into_inner);
        let Some(entry) = entries.get(id) else {
            return false;
        };
        entry.disable(reason.into());
        true
    }

    /// Resume dispatching to a plugin this process already loaded.
    ///
    /// The mirror of [`Self::disable`], and it exists because without it
    /// enabling is not the inverse of disabling: the module is still
    /// compiled and instantiated, so there is nothing to rebuild, and
    /// leaving the entry switched off would mean an admin who disabled a
    /// plugin by mistake could not undo it without restarting the server.
    ///
    /// Resets the consecutive-failure count. A plugin disabled by repeated
    /// failure is at or past the threshold, so re-enabling without clearing
    /// it would re-disable on the very next failure - which is not "enabled"
    /// in any sense an admin would recognise.
    ///
    /// Returns whether a plugin with that id was loaded at all. `false` means
    /// this process never compiled it - a plugin installed since boot, or a
    /// safe-mode run - and enabling then genuinely does need a restart.
    pub fn enable(&self, id: &PluginId) -> bool {
        let entries = self.entries.read().unwrap_or_else(PoisonError::into_inner);
        let Some(entry) = entries.get(id) else {
            return false;
        };
        entry.enable();
        true
    }

    /// A point-in-time health read for one plugin. Never touches the
    /// plugin's execution lock — see the module-level doc comment on why
    /// that makes this safe to call while the plugin is crash-looping.
    pub fn status(&self, id: &PluginId) -> Option<PluginStatusSnapshot> {
        let entries = self.entries.read().unwrap_or_else(PoisonError::into_inner);
        entries.get(id).map(|entry| entry.snapshot(id.clone()))
    }

    #[cfg(test)]
    fn instance_is_free(&self, id: &PluginId) -> bool {
        let entries = self.entries.read().unwrap_or_else(PoisonError::into_inner);
        entries
            .get(id)
            .is_some_and(|entry| entry.instance.try_lock().is_ok())
    }

    fn enabled_entry(&self, id: &PluginId) -> Option<Arc<PluginEntry>> {
        let entries = self.entries.read().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get(id)?;
        entry.is_enabled().then(|| entry.clone())
    }

    /// Fires `export` on plugin `id` and does not wait for it. Failure —
    /// missing plugin, trap, timeout, an answer that can't be read — is
    /// folded into that plugin's failure count and is otherwise invisible to
    /// the caller: an action can never block a request or change its
    /// outcome, by construction, since this returns nothing to change it
    /// with.
    pub fn run_action<Req: Serialize>(&self, id: &PluginId, export: &str, req: &Req) {
        let Some(entry) = self.enabled_entry(id) else {
            return;
        };
        let arg = match serde_json::to_vec(req) {
            Ok(arg) => arg,
            Err(e) => {
                entry.record_failure(format!("could not serialise action argument: {e}"));
                return;
            }
        };
        let export = export.to_string();
        let deadline = self.call_deadline;
        let wall_bound = self.wall_bound();
        // Held for the lifetime of the spawned task, not just this method —
        // see the struct doc on `PluginHost::engine` for why a detached call
        // needs its own claim on the engine that enforces its deadline.
        let engine = Arc::clone(&self.engine);
        // Cloned rather than moved into the blocking closure: `entry` stays
        // with this outer task so it is still there to record against no
        // matter how the blocking task ends, including a Rust-level panic
        // inside it (distinct from a wasm trap, which never panics — that's
        // the point of the rest of this module).
        let call_entry = Arc::clone(&entry);

        tokio::spawn(async move {
            let blocking_engine = Arc::clone(&engine);
            let outcome = bounded_call(wall_bound, move || {
                let result = locked_call(&blocking_engine, &call_entry, &export, &arg, deadline);
                drop(blocking_engine);
                result
            })
            .await;
            drop(engine);

            match outcome {
                CallEnd::Done(Ok(_)) => entry.record_success(),
                CallEnd::Done(Err(PluginCallError::InstanceBusy)) => entry.record_busy(),
                CallEnd::Done(Err(err)) => entry.record_failure(err.to_string()),
                CallEnd::Panicked(join_err) => {
                    entry.record_failure(format!("plugin call task panicked: {join_err}"));
                }
                CallEnd::WallClock => entry.record_failure(wall_clock_reason(deadline)),
            }
        });
    }

    /// Runs `export` on plugin `id` as a filter, bounded by this host's
    /// call deadline, and resolves to [`FilterOutcome::Ran`] on success or
    /// [`FilterOutcome::CouldNotRun`] — applying the manifest's
    /// [`FailureMode`] — on any failure, including the plugin not existing.
    pub async fn run_filter<Req, Resp>(
        &self,
        id: &PluginId,
        export: &str,
        req: &Req,
    ) -> FilterOutcome<Resp>
    where
        Req: Serialize,
        Resp: DeserializeOwned + Send + 'static,
    {
        match self.run_query(id, export, req).await {
            Ok(resp) => FilterOutcome::Ran(resp),
            Err(reason) => FilterOutcome::could_not_run(self.failure_mode_for(id), reason),
        }
    }

    /// Runs `export` on plugin `id` and returns its answer, or the reason
    /// there is not one.
    ///
    /// The same machinery [`Self::run_filter`] uses, without the
    /// [`FailureMode`] on top. The two are not interchangeable and the
    /// difference is the point: a filter that cannot run still has to yield
    /// a verdict, so it falls back to what the manifest declared. A caller
    /// with no safe default - one rendering a page, say, where "assume it
    /// said yes" means nothing - needs the failure itself, and substituting
    /// a default here would be inventing an answer the plugin never gave.
    ///
    /// # Errors
    /// The reason the call could not be completed: the plugin is missing or
    /// disabled, its argument or answer would not serialise, it trapped, it
    /// ran past the deadline, or its task panicked. Every one of these also
    /// counts against the plugin's failure budget, exactly as it would on
    /// the filter path.
    pub async fn run_query<Req, Resp>(
        &self,
        id: &PluginId,
        export: &str,
        req: &Req,
    ) -> Result<Resp, String>
    where
        Req: Serialize,
        Resp: DeserializeOwned + Send + 'static,
    {
        let Some(entry) = self.enabled_entry(id) else {
            return Err(format!("plugin {id} is not available to run"));
        };
        let arg = match serde_json::to_vec(req) {
            Ok(arg) => arg,
            Err(e) => {
                let reason = format!("could not serialise the call argument: {e}");
                entry.record_failure(reason.clone());
                return Err(reason);
            }
        };
        let export = export.to_string();
        let deadline = self.call_deadline;
        // See the matching comment in `run_action`: cloned, not moved, so
        // `entry` is still here to record against even if the blocking task
        // itself panics rather than returning a caught call error.
        let call_entry = Arc::clone(&entry);
        let engine = Arc::clone(&self.engine);

        let outcome = bounded_call(self.wall_bound(), move || {
            locked_call(&engine, &call_entry, &export, &arg, deadline)
        })
        .await;

        match outcome {
            CallEnd::Done(Ok(bytes)) => match serde_json::from_slice::<Resp>(&bytes) {
                Ok(resp) => {
                    entry.record_success();
                    Ok(resp)
                }
                Err(e) => {
                    let reason = format!("the plugin's answer did not parse: {e}");
                    entry.record_failure(reason.clone());
                    Err(reason)
                }
            },
            CallEnd::Done(Err(call_err)) => {
                let reason = call_err.to_string();
                if matches!(call_err, PluginCallError::InstanceBusy) {
                    entry.record_busy();
                } else {
                    entry.record_failure(reason.clone());
                }
                Err(reason)
            }
            CallEnd::Panicked(join_err) => {
                let reason = format!("plugin call task panicked: {join_err}");
                entry.record_failure(reason.clone());
                Err(reason)
            }
            CallEnd::WallClock => {
                let reason = wall_clock_reason(deadline);
                entry.record_failure(reason.clone());
                Err(reason)
            }
        }
    }

    /// How long a caller waits, in wall-clock time, before it stops waiting
    /// for a call: the deadline plus a little slack so that a plugin which
    /// is merely slow *in wasm* is still stopped by its epoch trap, with the
    /// more specific error, rather than by this.
    fn wall_bound(&self) -> Duration {
        self.call_deadline + self.engine.tick() * 4
    }

    /// What `id`'s manifest declared it is, or `None` if nothing is
    /// registered under that id.
    ///
    /// Exists so a dispatch site can route only to plugins that claim the
    /// shape it is about to call. Asking an action plugin to answer a filter
    /// export would fail, and a failure on a filter resolves to the manifest's
    /// `FailureMode` - which defaults to *closed*. A single non-filter plugin
    /// registered as a filter would therefore refuse every invoice on the
    /// instance, for as long as it stayed installed.
    #[must_use]
    pub fn kind(&self, id: &PluginId) -> Option<PluginKind> {
        self.registry
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .map(|manifest| manifest.kind)
    }

    fn failure_mode_for(&self, id: &PluginId) -> FailureMode {
        self.registry
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .and_then(|manifest| manifest.failure_mode)
            .unwrap_or(FailureMode::Closed)
    }
}

/// How a bounded call ended.
enum CallEnd<T> {
    Done(Result<T, PluginCallError>),
    Panicked(tokio::task::JoinError),
    /// The wall-clock bound elapsed first.
    WallClock,
}

fn wall_clock_reason(deadline: Duration) -> String {
    format!(
        "plugin call exceeded its {deadline:?} wall-clock deadline (waiting for the instance \
         or inside a host call, where the wasm tick count does not run)"
    )
}

/// Runs `call` on a blocking thread and stops waiting for it after `bound`
/// of wall-clock time.
///
/// The epoch deadline only counts time spent executing wasm. Time queueing
/// for the instance lock, or inside a host call such as a storage query,
/// passes unmeasured, so a plugin slow in either place held its caller for as
/// long as it liked while its deadline reported itself satisfied. This is the
/// bound on what the caller waits.
///
/// It does **not** cancel the blocking thread: a thread inside a host call
/// cannot be interrupted from outside. What happens to it is bounded
/// separately. It cannot start late (see [`locked_call`]: waiting for the
/// lock gives up at the deadline) and when its host call finally returns the
/// epoch has long since passed the call's deadline, so the next epoch check
/// (function entry or loop back-edge, not every instruction) traps; a plugin
/// that returns straight after the host call simply completes. Either way
/// the instance lock is released. Until the host call returns the lock stays
/// held, which is why host-call implementations must bound their own time
/// (see [`PluginHostCalls`](super::runtime::PluginHostCalls)) - a sync call
/// cannot be cancelled from here - and why the host call's effect may still
/// land after the caller was told the deadline passed: a timeout is not
/// proof the effect did not happen. The warning logged for the call is what
/// makes that contention visible.
async fn bounded_call<T, F>(bound: Duration, call: F) -> CallEnd<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, PluginCallError> + Send + 'static,
{
    match tokio::time::timeout(bound, tokio::task::spawn_blocking(call)).await {
        Ok(Ok(result)) => CallEnd::Done(result),
        Ok(Err(join_err)) => CallEnd::Panicked(join_err),
        Err(_elapsed) => CallEnd::WallClock,
    }
}

/// Takes the instance lock, waiting no longer than `deadline`, then runs the
/// call with whatever part of the deadline is left.
fn locked_call(
    engine: &PluginEngine,
    entry: &PluginEntry,
    export: &str,
    arg: &[u8],
    deadline: Duration,
) -> Result<Vec<u8>, PluginCallError> {
    let started = Instant::now();
    let mut instance = loop {
        match entry.instance.try_lock() {
            Ok(guard) => break guard,
            Err(TryLockError::Poisoned(poisoned)) => break poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                if started.elapsed() >= deadline {
                    return Err(PluginCallError::InstanceBusy);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    };
    // Won the lock with nothing left of the deadline: the caller has all but
    // stopped waiting, so starting the call would run it for nobody.
    let remaining = deadline.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err(PluginCallError::InstanceBusy);
    }
    instance.call_raw(export, arg, engine.ticks_for(remaining))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::time::{Duration, Instant};

    use serde::{Deserialize, Serialize};

    use super::super::runtime::fixtures;
    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Ping {
        n: u32,
    }

    /// A request that always fails to serialise — standing in for whatever
    /// real `Req` type might one day fail `serde_json::to_vec`, to prove the
    /// failure is actually recorded rather than silently swallowed.
    struct AlwaysFailsToSerialize;

    impl Serialize for AlwaysFailsToSerialize {
        fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom(
                "test-forced serialization failure",
            ))
        }
    }

    fn host(max_failures: u32) -> PluginHost {
        PluginHost::with_tick(
            Version::new(1, 0, 0),
            max_failures,
            Duration::from_millis(20),
            Duration::from_millis(5),
        )
    }

    fn manifest(id: &str, kind: &str, failure_mode: Option<&str>) -> Manifest {
        let failure_mode_line = failure_mode
            .map(|m| format!("failure_mode = {m:?}\n"))
            .unwrap_or_default();
        format!(
            r#"
                id = {id:?}
                version = "0.1.0"
                dependencies = ["ethpayserver:^1.0.0"]
                kind = {kind:?}
                {failure_mode_line}
            "#
        )
        .parse()
        .unwrap()
    }

    /// Ticket test 1: a panicking plugin, called repeatedly, ends up
    /// disabled with a reason an admin can read — and every one of those
    /// calls got a clean answer back, not a panic.
    #[tokio::test]
    async fn panicking_plugin_is_disabled_with_a_visible_reason() {
        let host = host(3);
        let id = PluginId::new("cash.random.panics").unwrap();
        host.register(
            manifest("cash.random.panics", "action", None),
            &fixtures::panicking_module(),
        )
        .unwrap();

        for _ in 0..3 {
            host.run_action(&id, "call", &Ping { n: 1 });
        }
        // `run_action` is fire-and-forget; give the spawned tasks a moment
        // to actually run against the (fast, local) plugin.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let status = host.status(&id).unwrap();
        assert!(!status.enabled, "expected the plugin to be disabled");
        let reason = status.disabled_reason.unwrap();
        assert!(
            reason.to_lowercase().contains("trap"),
            "reason should say it trapped: {reason}"
        );
    }

    /// Ticket test 2: a filter that never returns is interrupted by its
    /// deadline, the request completes (this test itself does), and the
    /// plugin ends up disabled.
    #[tokio::test]
    async fn deadline_disables_the_plugin_and_the_request_completes() {
        let host = host(1);
        let id = PluginId::new("cash.random.hangs").unwrap();
        host.register(
            manifest("cash.random.hangs", "filter", None),
            &fixtures::infinite_loop_module(),
        )
        .unwrap();

        let started = Instant::now();
        let outcome = host
            .run_filter::<_, Ping>(&id, "call", &Ping { n: 1 })
            .await;
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "took {elapsed:?} to come back"
        );
        assert!(
            matches!(outcome, FilterOutcome::CouldNotRun { allowed: false, .. }),
            "got {outcome:?}"
        );
        assert!(!host.status(&id).unwrap().enabled);
    }

    /// Ticket test 3: a plugin returning bytes that don't deserialise fails
    /// the filter (closed, since no failure mode was declared) instead of
    /// panicking the host.
    #[tokio::test]
    async fn garbage_answer_refuses_the_filter_without_panicking() {
        let host = host(5);
        let id = PluginId::new("cash.random.garbage").unwrap();
        host.register(
            manifest("cash.random.garbage", "filter", None),
            &fixtures::garbage_module(),
        )
        .unwrap();

        let outcome = host
            .run_filter::<_, Ping>(&id, "call", &Ping { n: 1 })
            .await;

        assert!(
            matches!(outcome, FilterOutcome::CouldNotRun { allowed: false, .. }),
            "got {outcome:?}"
        );
    }

    /// Ticket test 4: a filter that fails with no declared failure mode is
    /// refused, not allowed — the manifest's own parse-time default
    /// (`FailureMode::Closed`) must actually be what the host applies.
    #[tokio::test]
    async fn filter_with_no_declared_failure_mode_fails_closed() {
        let host = host(5);
        let id = PluginId::new("cash.random.strictfilter").unwrap();
        host.register(
            manifest("cash.random.strictfilter", "filter", None),
            &fixtures::panicking_module(),
        )
        .unwrap();

        let outcome = host
            .run_filter::<_, Ping>(&id, "call", &Ping { n: 1 })
            .await;

        assert!(
            matches!(outcome, FilterOutcome::CouldNotRun { allowed: false, .. }),
            "a filter with no declared failure_mode must fail closed, got {outcome:?}"
        );
    }

    /// The contrasting case: a filter that declares `failure_mode = "open"`
    /// proceeds when it fails, proving the host actually reads the
    /// manifest's choice rather than hardcoding closed.
    #[tokio::test]
    async fn filter_with_open_failure_mode_proceeds_on_failure() {
        let host = host(5);
        let id = PluginId::new("cash.random.openfilter").unwrap();
        host.register(
            manifest("cash.random.openfilter", "filter", Some("open")),
            &fixtures::panicking_module(),
        )
        .unwrap();

        let outcome = host
            .run_filter::<_, Ping>(&id, "call", &Ping { n: 1 })
            .await;

        assert!(
            matches!(outcome, FilterOutcome::CouldNotRun { allowed: true, .. }),
            "got {outcome:?}"
        );
    }

    /// Ticket test 5: while a plugin is crash-looping (or simply mid-call),
    /// a status read — the admin page's data source — stays fast. It never
    /// waits on the same lock a stuck call is holding.
    ///
    /// The call deadline here (500ms) is deliberately far longer than the
    /// status budget asserted below (150ms) — not the same order of
    /// magnitude, as an earlier version of this test had it. With a loose
    /// gap, a `status()` that regressed into blocking on the stuck call's
    /// own instance lock would still finish inside the budget by accident,
    /// since the call itself gets interrupted quickly too, and the test
    /// would keep passing against containment that no longer holds. With
    /// this gap, a regression has to wait out most of the call's 500ms
    /// budget before the lock frees up, which blows through the 150ms
    /// budget unmistakably.
    #[tokio::test]
    async fn status_reads_stay_fast_while_a_plugin_is_stuck() {
        let host = Arc::new(PluginHost::with_tick(
            Version::new(1, 0, 0),
            100,
            Duration::from_millis(500),
            Duration::from_millis(10),
        ));
        let id = PluginId::new("cash.random.stuck").unwrap();
        host.register(
            manifest("cash.random.stuck", "action", None),
            &fixtures::infinite_loop_module(),
        )
        .unwrap();

        // Kick off a call that will occupy the plugin's instance lock for
        // roughly its whole (comparatively long) deadline.
        let in_flight = host.clone();
        let in_flight_id = id.clone();
        tokio::spawn(async move {
            in_flight.run_action(&in_flight_id, "call", &Ping { n: 1 });
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let started = Instant::now();
        let status = tokio::time::timeout(Duration::from_millis(150), async { host.status(&id) })
            .await
            .unwrap();
        assert!(status.is_some());
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "status() took {:?}; a regression to lock contention would show up here as ~500ms",
            started.elapsed()
        );
    }

    /// Once disabled, the host stops calling into wasmtime for that plugin
    /// at all — the crash loop is bounded to `max_failures`, not unbounded.
    #[tokio::test]
    async fn a_disabled_plugin_is_never_called_again() {
        let host = host(2);
        let id = PluginId::new("cash.random.diesquick").unwrap();
        host.register(
            manifest("cash.random.diesquick", "action", None),
            &fixtures::panicking_module(),
        )
        .unwrap();

        for _ in 0..2 {
            host.run_action(&id, "call", &Ping { n: 1 });
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!host.status(&id).unwrap().enabled);

        for _ in 0..10 {
            host.run_action(&id, "call", &Ping { n: 1 });
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Failures stop accumulating past disablement: nothing after
        // disablement ever reached wasmtime to fail again.
        assert_eq!(host.status(&id).unwrap().consecutive_failures, 2);
    }

    /// A request that fails to serialise never reaches wasmtime, but it is
    /// still a real failure to run the call — it must count toward
    /// `max_failures` and show up via `status()`, not vanish silently.
    #[tokio::test]
    async fn run_action_serialization_failure_counts_as_a_failure() {
        let host = host(1);
        let id = PluginId::new("cash.random.badactionarg").unwrap();
        host.register(
            manifest("cash.random.badactionarg", "action", None),
            &fixtures::echo_module(),
        )
        .unwrap();

        host.run_action(&id, "call", &AlwaysFailsToSerialize);

        let status = host.status(&id).unwrap();
        assert!(
            !status.enabled,
            "a call that never made it to the plugin must still count as a failure"
        );
        assert!(status.disabled_reason.unwrap().contains("serialise"));
    }

    /// Same swallowed-failure bug, filter side: a serialisation failure must
    /// both apply the failure mode to the caller *and* be recorded against
    /// the plugin, not just the former.
    #[tokio::test]
    async fn run_filter_serialization_failure_counts_as_a_failure() {
        let host = host(1);
        let id = PluginId::new("cash.random.badfilterarg").unwrap();
        host.register(
            manifest("cash.random.badfilterarg", "filter", None),
            &fixtures::echo_module(),
        )
        .unwrap();

        let outcome = host
            .run_filter::<_, Ping>(&id, "call", &AlwaysFailsToSerialize)
            .await;

        assert!(
            matches!(outcome, FilterOutcome::CouldNotRun { allowed: false, .. }),
            "got {outcome:?}"
        );
        let status = host.status(&id).unwrap();
        assert!(
            !status.enabled,
            "a call that never made it to the plugin must still count as a failure"
        );
    }

    #[test]
    fn register_rejects_what_the_load_time_gate_rejects() {
        let host = host(3);
        // Dependency requirement the 1.0.0 test host does not satisfy.
        let bad: Manifest = r#"
            id = "cash.random.old"
            version = "0.1.0"
            dependencies = ["ethpayserver:^9.9.9"]
            kind = "action"
        "#
        .parse()
        .unwrap();

        let err = host.register(bad, &fixtures::echo_module()).unwrap_err();
        assert!(matches!(err, PluginHostError::Rejected(_)));
    }

    /// A module that fails to compile must not leave its id claimed in the
    /// registry — otherwise there is no way to retry a fix under the same
    /// id, since `status` reports the id absent while a re-registration
    /// attempt would hit the registry's duplicate-id rejection.
    #[test]
    fn a_failed_instantiation_leaves_the_id_free_to_retry() {
        let host = host(3);
        let id = PluginId::new("cash.random.retry").unwrap();
        let manifest = manifest("cash.random.retry", "action", None);

        let err = host
            .register(manifest.clone(), b"not a wasm module")
            .unwrap_err();
        assert!(matches!(err, PluginHostError::Wasm(_)));
        assert!(host.status(&id).is_none());

        host.register(manifest, &fixtures::echo_module()).unwrap();
        assert!(host.status(&id).unwrap().enabled);
    }
}

#[cfg(test)]
mod admin_toggle_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    use super::super::registry::host_version;
    use super::super::runtime::fixtures::echo_module;
    use super::*;

    fn manifest_for(id: &str) -> Manifest {
        let host = host_version();
        format!(
            r#"
            id = "{id}"
            version = "0.1.0"
            dependencies = ["ethpayserver:^{}.{}"]
            kind = "action"
            "#,
            host.major, host.minor
        )
        .parse()
        .unwrap()
    }

    fn loaded_host(id: &PluginId) -> PluginHost {
        let host = PluginHost::new(host_version(), 3, Duration::from_secs(2));
        host.register(manifest_for(id.as_str()), &echo_module())
            .unwrap();
        host
    }

    /// An admin disabling a plugin means stop running it, now.
    ///
    /// Without this the only recovery that does not need a restart would not
    /// actually recover anything: the row would say disabled while the
    /// plugin kept being consulted until someone bounced the process.
    #[test]
    fn disabling_takes_effect_immediately() {
        let id = PluginId::new("cash.random.billing").unwrap();
        let host = loaded_host(&id);

        assert!(host.status(&id).unwrap().enabled);
        assert!(host.disable(&id, "suspected of eating invoices"));

        let after = host.status(&id).unwrap();
        assert!(!after.enabled);
        assert_eq!(
            after.disabled_reason.as_deref(),
            Some("suspected of eating invoices")
        );
    }

    /// And enabling is its inverse, in the same process.
    ///
    /// Found by driving the real HTTP API: enable cleared the database row
    /// but left the live entry disabled, so the plugin list came back reading
    /// `enabled=true, loaded=false` with the old disable reason still
    /// attached - which looks exactly like the enable having failed. The
    /// module is already compiled and instantiated, so there is nothing to
    /// rebuild and no reason an accidental disable should cost a restart to
    /// undo.
    #[test]
    fn enabling_undoes_a_disable_without_a_restart() {
        let id = PluginId::new("cash.random.billing").unwrap();
        let host = loaded_host(&id);

        host.disable(&id, "a mistake");
        assert!(host.enable(&id));

        let after = host.status(&id).unwrap();
        assert!(after.enabled, "enable must be the inverse of disable");
        assert!(
            after.disabled_reason.is_none(),
            "a running plugin must not still carry the reason it was stopped, which an \
             admin would read as it still being stopped; got {:?}",
            after.disabled_reason
        );
    }

    /// Re-enabling forgives the failure history.
    ///
    /// A plugin disabled by repeated failure sits at or past the threshold,
    /// so enabling without clearing the count would re-disable it on the very
    /// next failure - which is not "enabled" in any sense an admin would
    /// recognise.
    #[test]
    fn enabling_resets_the_failure_count_that_disabled_it() {
        let id = PluginId::new("cash.random.billing").unwrap();
        let host = loaded_host(&id);

        // Drive it to the disable threshold the way a misbehaving plugin
        // would, rather than setting the state directly.
        let entries = host.entries.read().unwrap();
        let entry = entries.get(&id).unwrap().clone();
        drop(entries);
        for _ in 0..3 {
            entry.record_failure("trapped".to_string());
        }
        assert!(!host.status(&id).unwrap().enabled);
        assert_eq!(host.status(&id).unwrap().consecutive_failures, 3);

        host.enable(&id);

        let after = host.status(&id).unwrap();
        assert!(after.enabled);
        assert_eq!(
            after.consecutive_failures, 0,
            "a re-enabled plugin that keeps its failure count is one failure from being \
             disabled again"
        );
    }

    /// Neither toggle invents a plugin that was never loaded. `false` is the
    /// honest answer, and the caller still has a database row to update.
    #[test]
    fn toggling_a_plugin_this_process_never_loaded_reports_false() {
        let host = PluginHost::new(host_version(), 3, Duration::from_secs(2));
        let absent = PluginId::new("cash.random.absent").unwrap();

        assert!(!host.disable(&absent, "whatever"));
        assert!(!host.enable(&absent));
    }

    /// A plugin registered with host calls can actually reach them. Without
    /// this, `register_with_calls` could quietly instantiate without imports
    /// and every other test here would still pass, because none of them
    /// exercise a plugin that calls back.
    #[tokio::test]
    async fn a_plugin_registered_with_calls_can_use_them() {
        use std::sync::Mutex as StdMutex;

        struct Recording(StdMutex<Vec<Vec<u8>>>);
        impl PluginHostCalls for Recording {
            fn storage_query(&self, request: &[u8]) -> Result<Vec<u8>, String> {
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(request.to_vec());
                Ok(br#"{"ok":true}"#.to_vec())
            }

            fn invoice_create(&self, _request: &[u8]) -> Result<Vec<u8>, String> {
                Err("this double issues no invoices".to_string())
            }

            fn merchant_volume(&self, _request: &[u8]) -> Result<Vec<u8>, String> {
                Err("this double reports no volume".to_string())
            }

            fn merchant_volumes(&self, _request: &[u8]) -> Result<Vec<u8>, String> {
                Err("this double reports no volume".to_string())
            }

            fn account_notice(&self, _request: &[u8]) -> Result<Vec<u8>, String> {
                Err("this double notifies no accounts".to_string())
            }

            fn account_standing(&self, _request: &[u8]) -> Result<Vec<u8>, String> {
                Err("this double reports no standing".to_string())
            }
        }

        let calls = Arc::new(Recording(StdMutex::new(Vec::new())));
        let host = PluginHost::new(host_version(), 3, Duration::from_millis(500));
        host.register_with_calls(
            manifest_for("cash.random.asks"),
            &crate::runtime::fixtures::host_calling_module(),
            Some(calls.clone()),
        )
        .unwrap();

        let outcome = host
            .run_filter::<_, serde_json::Value>(
                &PluginId::new("cash.random.asks").unwrap(),
                "call",
                &serde_json::json!({"statements": []}),
            )
            .await;

        assert!(
            matches!(outcome, FilterOutcome::Ran(_)),
            "the plugin could not complete a call that goes through a host import: {outcome:?}"
        );
        assert_eq!(
            calls.0.lock().unwrap_or_else(PoisonError::into_inner).len(),
            1,
            "the host import was never reached"
        );
    }

    /// A host-call double whose storage query sleeps: the plugin is not
    /// executing wasm while it does, so no epoch tick counts the time.
    struct SlowStorage(Duration);
    impl PluginHostCalls for SlowStorage {
        fn storage_query(&self, _request: &[u8]) -> Result<Vec<u8>, String> {
            std::thread::sleep(self.0);
            Ok(br#"{"ok":true}"#.to_vec())
        }
        fn invoice_create(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            Err("unused".to_string())
        }
        fn merchant_volume(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            Err("unused".to_string())
        }
        fn merchant_volumes(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            Err("unused".to_string())
        }
        fn account_notice(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            Err("unused".to_string())
        }
        fn account_standing(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            Err("unused".to_string())
        }
    }

    fn host_with_slow_storage(block: Duration) -> (Arc<PluginHost>, PluginId) {
        let host = Arc::new(PluginHost::with_tick(
            host_version(),
            100,
            Duration::from_millis(50),
            // A coarse tick widens the slack between the lock-wait give-up
            // (the deadline) and the outer wall bound (deadline + 4 ticks),
            // so a delayed thread start under load cannot turn the queued
            // caller's `InstanceBusy` into the outer bound firing first.
            Duration::from_millis(25),
        ));
        host.register_with_calls(
            manifest_for("cash.random.slowstore"),
            &crate::runtime::fixtures::host_calling_module(),
            Some(Arc::new(SlowStorage(block))),
        )
        .unwrap();
        (host, PluginId::new("cash.random.slowstore").unwrap())
    }

    /// A plugin blocked inside a host call, not computing, must fail the
    /// deadline. Compute-bound plugins are already stopped by the epoch, so
    /// only a blocking host call proves the wall-clock bound.
    #[tokio::test]
    async fn a_plugin_blocked_in_a_host_call_fails_the_deadline() {
        let (host, id) = host_with_slow_storage(Duration::from_millis(800));

        let started = Instant::now();
        let result = host
            .run_query::<_, serde_json::Value>(&id, "call", &serde_json::json!({}))
            .await;

        assert!(
            started.elapsed() < Duration::from_millis(400),
            "the caller waited {:?} on a 50ms deadline",
            started.elapsed()
        );
        assert!(result.unwrap_err().contains("wall-clock"));
        assert_eq!(host.status(&id).unwrap().consecutive_failures, 1);
    }

    /// The blocked thread is abandoned, not cancelled: it still holds the
    /// instance until the host call returns, a caller queued behind it gives
    /// up at the deadline rather than waiting out the holder, and once the
    /// host call returns the instance is released so the plugin is usable
    /// again.
    #[tokio::test]
    async fn lock_wait_is_bounded_and_the_instance_recovers_after_the_blocked_call() {
        let (host, id) = host_with_slow_storage(Duration::from_millis(300));

        let holder = {
            let (host, id) = (host.clone(), id.clone());
            tokio::spawn(async move {
                host.run_query::<_, serde_json::Value>(&id, "call", &serde_json::json!({}))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;

        let started = Instant::now();
        let queued = host
            .run_query::<_, serde_json::Value>(&id, "call", &serde_json::json!({}))
            .await;
        assert!(started.elapsed() < Duration::from_millis(200));
        let queued_reason = queued.unwrap_err();
        assert!(
            queued_reason.contains("waiting for the plugin's instance"),
            "the queued caller should give up as busy, not on the outer bound: {queued_reason}"
        );
        assert!(holder.await.unwrap().unwrap_err().contains("wall-clock"));
        // Only the call that held the instance counts against the plugin;
        // queueing behind it must not push a healthy plugin to disablement.
        assert_eq!(host.status(&id).unwrap().consecutive_failures, 1);

        // Let the abandoned host call return and release the lock.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            host.instance_is_free(&id),
            "the abandoned call still holds the instance"
        );
    }

    /// The fire-and-forget path has its own copy of the wall-clock arm: a
    /// detached action blocked in a host call must still be recorded as a
    /// failure at the bound, well before the host call itself returns.
    #[tokio::test]
    async fn a_detached_action_blocked_in_a_host_call_is_recorded_as_a_failure() {
        let (host, id) = host_with_slow_storage(Duration::from_millis(800));

        host.run_action(&id, "call", &serde_json::json!({}));
        // Past the outer bound (deadline + 4 ticks = 150ms), well short of 800ms.
        tokio::time::sleep(Duration::from_millis(400)).await;

        assert_eq!(host.status(&id).unwrap().consecutive_failures, 1);
        assert!(
            !host.instance_is_free(&id),
            "the abandoned host call should still hold the instance"
        );
    }

    /// The same module registered *without* calls must not trap - the import
    /// is defined and unbacked, which is an error the plugin can report.
    #[tokio::test]
    async fn the_same_plugin_registered_without_calls_still_loads() {
        let host = PluginHost::new(host_version(), 3, Duration::from_millis(500));
        host.register(
            manifest_for("cash.random.asksnothing"),
            &crate::runtime::fixtures::host_calling_module(),
        )
        .expect("a plugin importing host calls must load even when nothing backs them");
    }
}
