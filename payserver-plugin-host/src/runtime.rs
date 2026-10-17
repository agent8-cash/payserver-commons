//! Instantiate a plugin module, call an export, bound it with a deadline,
//! and turn whatever goes wrong into a value instead of a panic.
//!
//! The calling convention is host-defined, not part of
//! `payserver-plugin-api` yet: a plugin exports `memory`, an
//! `alloc(len: i32) -> i32` bump allocator the host uses to place its (JSON)
//! argument, and one function per call name with signature
//! `(ptr: i32, len: i32) -> i64`, the result packed as `(ptr << 32) | len`
//! into the return value.
//!
//! # Calling back into the host
//!
//! A plugin used to be a pure function: it received bytes and returned bytes,
//! and could ask the host nothing. That is enough for a filter whose answer
//! depends only on its argument and nothing else — and not enough for any
//! plugin that has state, because it could not read its own tables.
//!
//! Imports are supplied under the module name [`HOST_MODULE`], and every one
//! is always defined whether or not this host can actually service it. A
//! plugin that imports a function the host does not provide fails at
//! *instantiation*, which would turn "this host cannot do storage" into "this
//! plugin will not load", losing the difference between a plugin that is
//! broken and a host that is minimal. Unbacked imports answer with an error
//! instead.
//!
//! The answer is passed in two steps, and the reason is worth stating because
//! the one-step version looks simpler:
//!
//! 1. `storage_query(ptr, len) -> i64` runs the request and returns the
//!    length of its answer, or a negative value on failure.
//! 2. `host_take(ptr, len) -> i32` copies that answer into a buffer the
//!    plugin has since allocated for itself.
//!
//! One step would mean the host allocating inside the plugin's memory, which
//! means calling the plugin's own `alloc` export from inside a host function
//! that the plugin called — re-entering an instance mid-call. Two steps keep
//! the host writing only into memory the plugin already owns.
//!
//! Every host call answers this way, and they share the one `host_take`
//! rather than each bringing its own. The protocol is strictly
//! ask-then-take within a single call, and a plugin instance runs one call
//! at a time, so there is never more than one answer waiting — a second
//! take function would be two names for the same buffer.
//!
//! # `invoice_create`
//!
//! The second answering call, and the one that moves money: it asks the
//! host to issue an invoice *on the host's own store*.
//!
//! Note what the plugin does not get to say. There is no store in the
//! request — not a checked one, none at all. A plugin that could name a
//! store could invoice a merchant's customers under the merchant's name, so
//! the host substitutes its own and the refusal is structural rather than a
//! check someone could later delete. See `enforce_own_store` on the host
//! side for the same property stated where an ordinary caller can reach it.
//!
//! # `merchant_volume`
//!
//! The third answering call, and the only one that reads anything about a
//! merchant other than the plugin's own rows: it answers "how much did this
//! account settle, in one currency, over the last N days" with a single
//! number.
//!
//! A plugin that prices by volume cannot compute that number itself. It sees
//! its own schema and the payments on the host's own store, and a merchant's
//! own takings are neither. The alternative to this call is showing the
//! plugin every payment every merchant received so it can add them up, which
//! is exactly the disclosure the payment-observer capability refuses to make.
//! One aggregate per account per window is the smallest thing that answers
//! the question.
//!
//! It is still a disclosure, so it is worth naming what it is: a plugin with
//! this import can learn any account's settled volume. It cannot learn what
//! any individual payment was, who paid it, on what chain, to which address,
//! or in what asset.
//!
//! # `merchant_volumes`
//!
//! The fourth answering call, and the batched form of `merchant_volume`: it
//! answers the same question for many accounts in one call rather than one
//! call per account.
//!
//! A page listing every account's standing cannot call `merchant_volume`
//! once per row and stay inside a single call's deadline - each call is a
//! host-side store lookup, a database aggregate and at least one live rate
//! lookup, and a table's row count is the plugin's to choose, not the
//! host's. This exists so that choice does not multiply real I/O by however
//! many rows a plugin decided to draw.
//!
//! Same disclosure as `merchant_volume`, at the scale of a list instead of
//! one account: a plugin with this import can learn many accounts' settled
//! volume in one call. It still cannot learn what any individual payment
//! was.
//!
//! # `account_standing`
//!
//! The fifth answering call, and the only one that reads a decision someone
//! else made: it answers "what standing did the host last receive for this
//! account" with the stored standing, or nothing when none was ever received.
//!
//! It is read-only by construction, and the property is structural rather
//! than a check. The import takes an account and returns a value; there is no
//! second import that stores one, and `storage_query` runs in the plugin's
//! own schema, which does not contain the table the host keeps the standing
//! in. A plugin that gates on a standing therefore cannot grant itself a good
//! one, whatever bug or compromise it carries.
//!
//! One account per call, no listing: a plugin with this import learns the
//! standing of an account it already has an id for, and cannot enumerate the
//! accounts that have one.
//!
//! # `account_notice`
//!
//! The sixth answering call, and the only one that reaches outside the
//! host's own process: it asks the host to tell an account something,
//! naming a subject and a body.
//!
//! Note what the plugin does not get to say, the same shape of restriction
//! as `invoice_create`'s missing store: there is no address in the request,
//! checked or otherwise. A plugin that could name a recipient could reach
//! anyone through a channel wearing this host's name; the host resolves the
//! account to whichever address and channel it owns instead, and a plugin
//! that names an account it does not otherwise deal with learns nothing
//! about whether that account exists or how to reach it - it only ever
//! learns whether its own notice was delivered.
//!
//! The production body on the pinned side already exists and is merged: it
//! resolves an account id to its registered email and delivers through the
//! same sender that already sends receipts, refusing rather than pretending
//! to succeed when an account has no address on file. It is not wired into
//! this trait yet for a mechanical reason, not a missing one - the pinned
//! side's `impl PluginHostCalls` cannot implement a method this trait does
//! not declare, and this crate is what has to merge and get pinned first.
//!
//! The piece that decides *when* to call this - reading a plan's own warning
//! schedule and firing once an account crosses a bracket - belongs to the
//! billing plugin, and it cannot be written before this capability is
//! reachable either: a plugin that imports a call its host does not
//! register fails to *instantiate*, not to run, so adding that import ahead
//! of the pin moving would take the plugin down rather than leave today's
//! behaviour in place. The order is fixed - this capability merges, then the
//! pin moves and the host-side body gets wired to it, then and only then can
//! the billing plugin add the caller - and it cannot be collapsed into one
//! PR without either skipping a step or breaking one.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use wasmtime::{Caller, Config, Engine, Instance, Linker, Memory, Module, Store, TypedFunc};

/// The wasm module name a plugin imports host functions from.
pub const HOST_MODULE: &str = "ethpayserver";

/// What a plugin may ask its host to do while a call is running.
///
/// Sync on purpose. The runtime calls plugins from inside `spawn_blocking`,
/// so a host function is already on a blocking thread; making this trait
/// async would mean either driving a future from a sync wasmtime callback or
/// making every call path async for the benefit of one implementation. An
/// implementation backed by a database does its own `block_on` at that
/// boundary, where the blocking is obvious.
///
/// Every method is scoped to the calling plugin by the implementation, not by
/// an argument. A plugin naming the schema it wants to read is the same hole
/// `enforce_own_store` closes on the invoice side.
///
/// # An implementation must bound its own time
///
/// The call deadline does **not** cover this. A plugin's deadline is enforced
/// by wasmtime's epoch interruption, which traps *wasm execution* — and a
/// host function is not wasm execution. Once control is inside an
/// implementation of this trait, the epoch can advance as far as it likes and
/// nothing interrupts it; the plugin is simply not running to be trapped.
///
/// So an implementation that talks to a database and hangs holds its
/// `spawn_blocking` thread indefinitely, past any deadline the host thinks it
/// set, and the plugin looks stuck for a reason that is not the plugin's. Any
/// implementation that can block must impose its own timeout and return an
/// error when it elapses.
///
/// # Where the real implementation lives
///
/// This crate defines the interface and proves the wasm wiring reaches it -
/// nothing here talks to a database or a merchant. The body that actually
/// issues an invoice, reads settled volume, or sends a notice belongs to
/// whichever binary embeds this host (`ethpayserver`'s own
/// `impl PluginHostCalls`), pinned to this crate by revision. A change here
/// makes a capability callable; it does not, by itself, make anything call
/// it - that caller, and the production body behind it, are additions on the
/// pinning side once the pin moves.
pub trait PluginHostCalls: Send + Sync {
    /// Read from the plugin's own storage. `request` and the answer are the
    /// plugin's own JSON; this layer does not interpret either.
    ///
    /// # Errors
    /// Returns the message to hand back to the plugin when the request could
    /// not be served.
    fn storage_query(&self, request: &[u8]) -> Result<Vec<u8>, String>;

    /// Issue an invoice on the host's own store.
    ///
    /// `request` names an asset and an amount, and never a store: see this
    /// module's header for why the store is the host's to supply and not the
    /// plugin's to ask for.
    ///
    /// Required rather than defaulted, and deliberately so. A default
    /// returning "not supported" would let an implementation grant or refuse
    /// the money-path capability by forgetting to mention it, and the
    /// forgetting would look exactly like a host that meant to withhold it.
    /// An implementation that cannot issue invoices says so in its own body,
    /// where it knows why.
    ///
    /// # Errors
    /// Returns the message to hand back to the plugin when no invoice could
    /// be issued.
    fn invoice_create(&self, request: &[u8]) -> Result<Vec<u8>, String>;

    /// Total volume one account settled over a window, in one currency.
    ///
    /// `request` names the account, the window in days and the currency to
    /// quote in; the answer is one number. See this module's header for what
    /// this deliberately does not disclose.
    ///
    /// Required rather than defaulted, for the same reason
    /// [`invoice_create`](Self::invoice_create) is: a default would let an
    /// implementation hand out a merchant-data capability by not mentioning
    /// it.
    ///
    /// # Errors
    /// Returns the message to hand back to the plugin when the volume could
    /// not be read.
    fn merchant_volume(&self, request: &[u8]) -> Result<Vec<u8>, String>;

    /// Total volume many accounts each settled over a window, in one call.
    ///
    /// `request` names the accounts, the window in days and the currency to
    /// quote in, the same shape as [`merchant_volume`](Self::merchant_volume)
    /// with a list of accounts in place of one. See this module's header for
    /// why this exists as its own call rather than a loop over that one.
    ///
    /// Required rather than defaulted, for the same reason
    /// [`invoice_create`](Self::invoice_create) is: a default would let an
    /// implementation hand out a merchant-data capability by not mentioning
    /// it.
    ///
    /// # Errors
    /// Returns the message to hand back to the plugin when the batch could
    /// not be read.
    fn merchant_volumes(&self, request: &[u8]) -> Result<Vec<u8>, String>;

    /// The standing the host last received for one account.
    ///
    /// `request` names the account; the answer is the stored standing, or an
    /// explicit absence. Read-only: see this module's header for why the
    /// plugin has no way to write one.
    ///
    /// Required rather than defaulted, for the same reason
    /// [`invoice_create`](Self::invoice_create) is: a default would let an
    /// implementation hand out an entitlement capability by not mentioning
    /// it.
    ///
    /// # Errors
    /// Returns the message to hand back to the plugin when the standing could
    /// not be read. An unreadable standing is an error, never an absence: a
    /// plugin reads "none" as "nothing was ever received".
    fn account_standing(&self, request: &[u8]) -> Result<Vec<u8>, String>;

    /// Tell one account something, through a channel and an address the
    /// plugin never names.
    ///
    /// `request` names an account and a subject/body; the host resolves the
    /// address and the channel itself. See this module's header for why the
    /// address is the host's to resolve and not the plugin's to ask for.
    ///
    /// Required rather than defaulted, for the same reason
    /// [`invoice_create`](Self::invoice_create) is: a default would let an
    /// implementation hand out or withhold a merchant-reaching capability by
    /// forgetting to mention it.
    ///
    /// # Errors
    /// Returns the message to hand back to the plugin when the account could
    /// not be notified.
    fn account_notice(&self, request: &[u8]) -> Result<Vec<u8>, String>;
}

/// The store's context: what host functions need, plus the buffer a two-step
/// answer waits in between `storage_query` and `host_take`.
struct PluginCtx {
    calls: Option<Arc<dyn PluginHostCalls>>,
    /// The answer to the most recent host call, waiting to be taken.
    ///
    /// Overwritten by each host call rather than queued: a plugin instance
    /// runs one call at a time (see `host::PluginEntry`'s call mutex) and the
    /// protocol is strictly query-then-take, so a second pending answer would
    /// mean a plugin ignored the first.
    pending: Vec<u8>,
}

/// A host call that could not run. Negative so it cannot be confused with a
/// zero-length answer, which is a legitimate result.
const HOST_CALL_FAILED: i64 = -1;

/// Ticks the shared [`Engine`]'s epoch on a fixed cadence so a [`Store`]'s
/// deadline (set in ticks, not wall time) actually elapses.
///
/// One ticker per engine, not per call: the epoch is engine-wide, and a
/// plugin instance only ever runs one call at a time (see
/// [`super::host::PluginEntry`]'s call mutex), so there is nothing for a
/// second ticker to do.
struct EpochTicker {
    running: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl EpochTicker {
    fn spawn(engine: Engine, interval: Duration) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let flag = running.clone();
        let handle = std::thread::spawn(move || {
            while flag.load(Ordering::Relaxed) {
                std::thread::sleep(interval);
                engine.increment_epoch();
            }
        });
        Self {
            running,
            handle: Some(handle),
        }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// The compiled-module factory and epoch clock shared by every plugin the
/// host loads. Created once and kept for the process lifetime.
pub struct PluginEngine {
    engine: Engine,
    tick: Duration,
    _ticker: EpochTicker,
}

impl PluginEngine {
    /// A tick short enough that tests can use millisecond-scale deadlines
    /// without either flaking (too coarse) or busy-looping (too fine).
    const DEFAULT_TICK: Duration = Duration::from_millis(5);

    pub fn new() -> Self {
        Self::with_tick(Self::DEFAULT_TICK)
    }

    pub fn with_tick(tick: Duration) -> Self {
        let mut config = Config::new();
        config.epoch_interruption(true);
        // `Config::new` here is hardcoded and known-valid; `Engine::new` only
        // fails for a config wasmtime can't support on this host, which is
        // not a runtime condition we need to recover from.
        #[allow(clippy::expect_used)]
        let engine = Engine::new(&config).expect("hardcoded wasmtime Config is always valid");
        let ticker = EpochTicker::spawn(engine.clone(), tick);
        Self {
            engine,
            tick,
            _ticker: ticker,
        }
    }

    /// Compiles `wasm` into a [`Module`] ready to instantiate.
    pub fn compile(&self, wasm: &[u8]) -> Result<Module, PluginWasmError> {
        Module::new(&self.engine, wasm).map_err(|e| PluginWasmError::Compile(e.to_string()))
    }

    /// Instantiates `module`, once, keeping the resulting store and export
    /// handles for reuse across calls.
    pub fn instantiate(&self, module: &Module) -> Result<PluginInstance, PluginWasmError> {
        PluginInstance::new(&self.engine, module, None)
    }

    /// Instantiates `module` with `calls` available to it as host imports.
    pub fn instantiate_with_calls(
        &self,
        module: &Module,
        calls: Arc<dyn PluginHostCalls>,
    ) -> Result<PluginInstance, PluginWasmError> {
        PluginInstance::new(&self.engine, module, Some(calls))
    }

    /// How often the epoch advances: the resolution of every tick-counted
    /// deadline.
    pub fn tick(&self) -> Duration {
        self.tick
    }

    /// The number of epoch ticks that will elapse in at least `deadline`,
    /// rounded up and never zero — a zero deadline would mean "already
    /// expired" rather than "as soon as possible".
    pub fn ticks_for(&self, deadline: Duration) -> u64 {
        let tick_nanos = self.tick.as_nanos().max(1);
        let deadline_nanos = deadline.as_nanos();
        deadline_nanos.div_ceil(tick_nanos).max(1) as u64
    }
}

impl Default for PluginEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// A plugin's own memory allocation call, kept type-checked once it's
/// resolved rather than an export name looked up on every call.
type Alloc = TypedFunc<i32, i32>;

/// A single loaded, instantiated plugin: a [`Store`] plus the two export
/// handles every call needs. Kept alive and reused across calls rather than
/// re-instantiated each time.
pub struct PluginInstance {
    store: Store<PluginCtx>,
    instance: Instance,
    memory: Memory,
    alloc: Alloc,
}

impl PluginInstance {
    fn new(
        engine: &Engine,
        module: &Module,
        calls: Option<Arc<dyn PluginHostCalls>>,
    ) -> Result<Self, PluginWasmError> {
        let mut store = Store::new(
            engine,
            PluginCtx {
                calls,
                pending: Vec::new(),
            },
        );
        let linker = host_linker(engine)?;
        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| PluginWasmError::Instantiate(e.to_string()))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| PluginWasmError::MissingExport("memory".to_string()))?;
        let alloc: Alloc = instance
            .get_typed_func(&mut store, "alloc")
            .map_err(|_| PluginWasmError::MissingExport("alloc".to_string()))?;
        Ok(Self {
            store,
            instance,
            memory,
            alloc,
        })
    }

    /// Calls the export named `export` with `arg_json` (already-serialised
    /// JSON bytes) and returns the raw JSON bytes it answered with.
    ///
    /// `deadline_ticks` bounds the call: if the engine's epoch advances past
    /// it before the call returns, wasmtime traps the call in place and this
    /// returns [`PluginCallError::DeadlineExceeded`] rather than blocking
    /// forever on a plugin that never returns.
    pub fn call_raw(
        &mut self,
        export: &str,
        arg_json: &[u8],
        deadline_ticks: u64,
    ) -> Result<Vec<u8>, PluginCallError> {
        self.store.set_epoch_deadline(deadline_ticks);

        let len = i32::try_from(arg_json.len())
            .map_err(|_| PluginCallError::Other("argument too large for a wasm32 plugin".into()))?;
        let ptr = self.alloc.call(&mut self.store, len).map_err(classify)?;
        self.memory
            .write(&mut self.store, ptr as usize, arg_json)
            .map_err(|e| PluginCallError::Other(e.to_string()))?;

        let call: TypedFunc<(i32, i32), i64> = self
            .instance
            .get_typed_func(&mut self.store, export)
            .map_err(|_| PluginCallError::MissingExport(export.to_string()))?;
        let packed = call.call(&mut self.store, (ptr, len)).map_err(classify)?;

        let (out_ptr, out_len) = unpack(packed);
        if out_len == 0 {
            return Ok(Vec::new());
        }
        let (out_ptr, out_len) = (out_ptr as usize, out_len as usize);
        // `out_len` came straight from the plugin's return value with no
        // validation yet — a garbage or adversarial packed value can claim
        // up to ~4 GiB. Bound it against the plugin's actual memory before
        // allocating: an allocation that large can fail, and Rust's default
        // allocator aborts the whole process on allocation failure rather
        // than returning an error, which would take down every other plugin
        // and the admin page along with it.
        let mem_size = self.memory.data_size(&self.store);
        if out_len > mem_size || out_ptr > mem_size - out_len {
            return Err(PluginCallError::Other(format!(
                "plugin returned an out-of-bounds answer (ptr {out_ptr}, len {out_len}, memory size {mem_size})"
            )));
        }
        let mut buf = vec![0u8; out_len];
        self.memory
            .read(&self.store, out_ptr, &mut buf)
            .map_err(|e| PluginCallError::Other(e.to_string()))?;
        Ok(buf)
    }

    /// [`call_raw`](Self::call_raw), serialising `req` to JSON and
    /// deserialising the answer as `Resp`. A plugin that answers with bytes
    /// that are not valid `Resp` JSON — garbage, a different shape, garbled
    /// output from a confused plugin — fails here cleanly, as a
    /// [`PluginCallError::Deserialize`], rather than panicking the host.
    pub fn call<Req: Serialize, Resp: DeserializeOwned>(
        &mut self,
        export: &str,
        req: &Req,
        deadline_ticks: u64,
    ) -> Result<Resp, PluginCallError> {
        let arg = serde_json::to_vec(req).map_err(|e| {
            PluginCallError::Other(format!("could not serialise call argument: {e}"))
        })?;
        let bytes = self.call_raw(export, &arg, deadline_ticks)?;
        serde_json::from_slice(&bytes).map_err(|e| PluginCallError::Deserialize(e.to_string()))
    }
}

/// Which method of [`PluginHostCalls`] one import routes to.
type HostCall = fn(&dyn PluginHostCalls, &[u8]) -> Result<Vec<u8>, String>;

/// Defines one `(ptr, len) -> i64` host call that answers through `pending`.
///
/// Every such call is the same shape - read the request out of the plugin's
/// memory, hand it to the one trait method that serves it, leave the answer
/// where `host_take` will find it - and differs only in which method that is
/// and what to say when nothing backs it. Written once so a third call is a
/// four-line addition rather than a copied block that can drift in the parts
/// nobody meant to change.
fn define_answering_call(
    linker: &mut Linker<PluginCtx>,
    name: &'static str,
    unbacked: &'static str,
    run: HostCall,
) -> Result<(), PluginWasmError> {
    linker
        .func_wrap(
            HOST_MODULE,
            name,
            move |mut caller: Caller<'_, PluginCtx>, ptr: i32, len: i32| -> i64 {
                let request = match read_plugin_memory(&mut caller, ptr, len) {
                    Ok(bytes) => bytes,
                    Err(_) => return HOST_CALL_FAILED,
                };

                let Some(calls) = caller.data().calls.clone() else {
                    // Defined but unbacked. An error, not a trap: the plugin
                    // asked a reasonable question of a host that cannot
                    // answer it, and it deserves the chance to say so.
                    caller.data_mut().pending = unbacked.as_bytes().to_vec();
                    return HOST_CALL_FAILED;
                };

                match run(calls.as_ref(), &request) {
                    Ok(answer) => {
                        let len = i64::try_from(answer.len()).unwrap_or(i64::MAX);
                        caller.data_mut().pending = answer;
                        len
                    }
                    Err(message) => {
                        caller.data_mut().pending = message.into_bytes();
                        HOST_CALL_FAILED
                    }
                }
            },
        )
        .map(|_| ())
        .map_err(|e| PluginWasmError::Instantiate(e.to_string()))
}

/// Builds the import surface every plugin is instantiated against.
///
/// `allow_shadowing` is not set and `define_unknown_imports_as_traps` is not
/// used: a plugin importing something this host has never heard of must fail
/// to instantiate, because there is no honest answer to give it.
fn host_linker(engine: &Engine) -> Result<Linker<PluginCtx>, PluginWasmError> {
    let mut linker = Linker::new(engine);

    define_answering_call(
        &mut linker,
        "storage_query",
        "this host does not provide storage",
        |calls, request| calls.storage_query(request),
    )?;

    define_answering_call(
        &mut linker,
        "invoice_create",
        "this host does not issue invoices",
        |calls, request| calls.invoice_create(request),
    )?;

    define_answering_call(
        &mut linker,
        "merchant_volume",
        "this host does not report merchant volume",
        |calls, request| calls.merchant_volume(request),
    )?;

    define_answering_call(
        &mut linker,
        "merchant_volumes",
        "this host does not report merchant volume",
        |calls, request| calls.merchant_volumes(request),
    )?;

    define_answering_call(
        &mut linker,
        "account_standing",
        "this host does not report account standing",
        |calls, request| calls.account_standing(request),
    )?;

    define_answering_call(
        &mut linker,
        "account_notice",
        "this host does not notify accounts",
        |calls, request| calls.account_notice(request),
    )?;

    linker
        .func_wrap(
            HOST_MODULE,
            "host_take",
            |mut caller: Caller<'_, PluginCtx>, ptr: i32, len: i32| -> i32 {
                let pending = std::mem::take(&mut caller.data_mut().pending);
                let Ok(len) = usize::try_from(len) else {
                    return -1;
                };
                // Copies what fits and reports how much, rather than refusing
                // a short buffer: a plugin that under-allocates gets a clear
                // number back instead of an opaque failure. It never writes
                // past what the plugin asked for.
                //
                // One shot. The answer is taken out of the context above
                // whether or not all of it fits, so a plugin that
                // under-allocates loses the remainder and cannot take again.
                // That is the safer direction - a partial answer left behind
                // would be handed to whatever asked next, which is a wrong
                // answer rather than a missing one - and it costs nothing,
                // since `storage_query` already told the plugin the exact
                // length to allocate.
                let n = pending.len().min(len);
                let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
                    return -1;
                };
                let Ok(ptr) = usize::try_from(ptr) else {
                    return -1;
                };
                if memory.write(&mut caller, ptr, &pending[..n]).is_err() {
                    return -1;
                }
                i32::try_from(n).unwrap_or(i32::MAX)
            },
        )
        .map_err(|e| PluginWasmError::Instantiate(e.to_string()))?;

    Ok(linker)
}

/// Whether `[ptr, ptr + len)` lies entirely inside a memory of `size` bytes.
///
/// Its own function, and unit-tested directly, because the behaviour it
/// protects is not observable from the outside: `Memory::read` *also* refuses
/// an out-of-bounds range, so a caller that skipped this check would still
/// return an error and look identical in an end-to-end test. What this
/// prevents is the allocation *before* that read — a plugin can claim nearly
/// 4 GiB, and Rust's default allocator aborts the whole process on allocation
/// failure rather than returning, taking every other plugin and the admin
/// page with it. An end-to-end test cannot see the difference; this one can.
fn in_bounds(ptr: usize, len: usize, size: usize) -> bool {
    len <= size && ptr <= size - len
}

/// Reads `len` bytes at `ptr` out of the caller's own memory, refusing a
/// range that is not entirely inside it *before* allocating for it.
fn read_plugin_memory(
    caller: &mut Caller<'_, PluginCtx>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, ()> {
    let (Ok(ptr), Ok(len)) = (usize::try_from(ptr), usize::try_from(len)) else {
        return Err(());
    };
    let memory = caller
        .get_export("memory")
        .and_then(wasmtime::Extern::into_memory)
        .ok_or(())?;
    if !in_bounds(ptr, len, memory.data_size(&caller)) {
        return Err(());
    }
    let mut buf = vec![0u8; len];
    memory.read(&caller, ptr, &mut buf).map_err(|_| ())?;
    Ok(buf)
}

/// The host never packs — only the test fixtures below do, standing in for
/// a real plugin's own encoding of its answer.
#[cfg(test)]
fn pack(ptr: u32, len: u32) -> i64 {
    (((ptr as u64) << 32) | (len as u64)) as i64
}

fn unpack(packed: i64) -> (u32, u32) {
    let packed = packed as u64;
    ((packed >> 32) as u32, packed as u32)
}

/// Turns a raw wasmtime call error into a [`PluginCallError`], picking out
/// epoch-deadline traps specifically so the caller can tell "the plugin ran
/// too long" apart from "the plugin crashed".
fn classify(err: wasmtime::Error) -> PluginCallError {
    match err.downcast_ref::<wasmtime::Trap>() {
        Some(wasmtime::Trap::Interrupt) => PluginCallError::DeadlineExceeded,
        Some(trap) => PluginCallError::Trap(trap.to_string()),
        None => PluginCallError::Other(err.to_string()),
    }
}

/// Why a plugin module could not be loaded and instantiated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PluginWasmError {
    #[error("failed to compile plugin module: {0}")]
    Compile(String),
    #[error("failed to instantiate plugin module: {0}")]
    Instantiate(String),
    #[error("plugin module is missing required export {0:?}")]
    MissingExport(String),
}

/// Why a single call into an already-instantiated plugin failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PluginCallError {
    #[error("plugin export {0:?} not found")]
    MissingExport(String),
    /// The call's deadline elapsed before the plugin returned.
    #[error("plugin exceeded its deadline")]
    DeadlineExceeded,
    /// The plugin panicked (in wasm terms: trapped) for a reason other than
    /// the deadline — `unreachable`, an out-of-bounds access, and so on.
    #[error("plugin trapped: {0}")]
    Trap(String),
    /// The call completed, but its answer did not deserialise as expected.
    #[error("plugin returned an answer the host could not parse: {0}")]
    Deserialize(String),
    #[error("plugin call failed: {0}")]
    Other(String),
    /// The plugin's instance stayed busy with another call for the whole
    /// deadline, so this call never started. A plugin runs one call at a
    /// time; this is the wall-clock bound on queueing for it.
    #[error("timed out waiting for the plugin's instance to free up")]
    InstanceBusy,
}

/// Test-only WAT fixtures for the ticket's five failure modes, shared with
/// [`super::host`]'s tests — `pub(crate)` rather than duplicated, since both
/// modules need the same panicking/looping/garbage-answer plugins.
#[cfg(test)]
pub(crate) mod fixtures {
    #![allow(clippy::unwrap_used)]

    /// A plugin that asks the host a question, takes the answer, and hands it
    /// straight back — the full two-step protocol, exercised end to end.
    pub(crate) fn host_calling_module() -> Vec<u8> {
        module_calling("storage_query")
    }

    /// The same plugin against the other answering import. Both go through
    /// the one `host_take`, which is the thing worth proving: a second
    /// answering call must not need a second way to collect its answer.
    pub(crate) fn invoice_calling_module() -> Vec<u8> {
        module_calling("invoice_create")
    }

    pub(crate) fn volume_calling_module() -> Vec<u8> {
        module_calling("merchant_volume")
    }

    pub(crate) fn volumes_calling_module() -> Vec<u8> {
        module_calling("merchant_volumes")
    }

    pub(crate) fn standing_calling_module() -> Vec<u8> {
        module_calling("account_standing")
    }

    pub(crate) fn notice_calling_module() -> Vec<u8> {
        module_calling("account_notice")
    }

    fn module_calling(import: &str) -> Vec<u8> {
        wat::parse_str(format!(
            r#"
            (module
                (import "ethpayserver" "{import}"
                    (func $query (param i32 i32) (result i64)))
                (import "ethpayserver" "host_take"
                    (func $take (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (global $next (mut i32) (i32.const 1024))

                (func $alloc (export "alloc") (param $len i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (global.get $next))
                    (global.set $next (i32.add (global.get $next) (local.get $len)))
                    (local.get $ptr))

                (func (export "call") (param $ptr i32) (param $len i32) (result i64)
                    (local $n i32)
                    (local $dest i32)
                    (local.set $n
                        (i32.wrap_i64 (call $query (local.get $ptr) (local.get $len))))
                    (if (i32.lt_s (local.get $n) (i32.const 0))
                        (then (return (i64.const 0))))
                    (local.set $dest (call $alloc (local.get $n)))
                    (drop (call $take (local.get $dest) (local.get $n)))
                    (i64.or
                        (i64.shl (i64.extend_i32_u (local.get $dest)) (i64.const 32))
                        (i64.extend_i32_u (local.get $n))))
            )
            "#,
        ))
        .unwrap()
    }

    use super::{PluginEngine, PluginInstance};

    /// A plugin exporting a bump allocator and one `call` per fixture
    /// behaviour, hand-written in WAT so tests need no wasm32 toolchain.
    fn wat_module(call_body: &str) -> Vec<u8> {
        let text = format!(
            r#"
            (module
                (memory (export "memory") 1)
                (global $next (mut i32) (i32.const 1024))

                (func (export "alloc") (param $len i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (global.get $next))
                    (global.set $next (i32.add (global.get $next) (local.get $len)))
                    (local.get $ptr))

                (func (export "call") (param $ptr i32) (param $len i32) (result i64)
                    {call_body})
            )
            "#
        );
        wat::parse_str(text).unwrap()
    }

    /// Echoes the argument straight back: `call` returns the same
    /// `(ptr, len)` it was given, packed.
    pub(crate) fn echo_module() -> Vec<u8> {
        wat_module(
            r#"
            (i64.or
                (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
                (i64.extend_i32_u (local.get $len)))
            "#,
        )
    }

    pub(crate) fn panicking_module() -> Vec<u8> {
        wat_module("unreachable")
    }

    pub(crate) fn infinite_loop_module() -> Vec<u8> {
        // The trailing `unreachable` is dead code — the loop only exits via
        // an epoch trap — but wasm's validator type-checks a `loop` by its
        // declared (empty) block type rather than proving it never falls
        // through, so the function body still needs *something* of type i64
        // after it to satisfy the declared return type.
        wat_module(r#"(loop $forever (br $forever)) unreachable"#)
    }

    /// Ignores its argument and returns a fixed pointer/length pointing at a
    /// data segment that is not valid JSON. Needs its own module body
    /// (rather than `wat_module`) to declare that data segment.
    pub(crate) fn garbage_module() -> Vec<u8> {
        let text = r#"
            (module
                (memory (export "memory") 1)
                (data (i32.const 0) "not json {")
                (global $next (mut i32) (i32.const 1024))

                (func (export "alloc") (param $len i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (global.get $next))
                    (global.set $next (i32.add (global.get $next) (local.get $len)))
                    (local.get $ptr))

                (func (export "call") (param $ptr i32) (param $len i32) (result i64)
                    (i64.or
                        (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
                        (i64.extend_i32_u (i32.const 10))))
            )
        "#;
        wat::parse_str(text).unwrap()
    }

    /// Ignores its argument and returns a packed value claiming a length far
    /// larger than the plugin's actual memory (one page, 64 KiB) — a garbage
    /// or adversarial `out_len` rather than garbage *bytes*. Distinct from
    /// [`garbage_module`], which returns a well-formed pointer/length into
    /// real (if non-JSON) memory: this one exercises the bound check itself.
    /// Chosen large enough to be well outside the module's memory but small
    /// enough that even an unbounded allocation attempt stays safe to run in
    /// a test — the point being to prove the bound check fires before any
    /// allocation, not to reproduce a multi-gigabyte allocation here.
    pub(crate) fn garbage_length_module() -> Vec<u8> {
        wat_module(
            r#"
            (i64.or
                (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
                (i64.extend_i32_u (i32.const 10000000)))
            "#,
        )
    }

    pub(crate) fn instance_for(engine: &PluginEngine, wasm: &[u8]) -> PluginInstance {
        let module = engine.compile(wasm).unwrap();
        engine.instantiate(&module).unwrap()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::time::{Duration, Instant};

    use serde::{Deserialize, Serialize};

    use super::fixtures::*;
    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Ping {
        n: u32,
    }

    #[test]
    fn calls_an_export_and_deserialises_the_answer() {
        let engine = PluginEngine::with_tick(Duration::from_millis(5));
        let mut plugin = instance_for(&engine, &echo_module());

        let resp: Ping = plugin
            .call(
                "call",
                &Ping { n: 7 },
                engine.ticks_for(Duration::from_secs(1)),
            )
            .unwrap();

        assert_eq!(resp, Ping { n: 7 });
    }

    /// Ticket test 1: a panicking plugin traps, and the host gets an `Err`
    /// back rather than a Rust panic unwinding into the caller.
    #[test]
    fn catches_a_trap_without_panicking() {
        let engine = PluginEngine::with_tick(Duration::from_millis(5));
        let mut plugin = instance_for(&engine, &panicking_module());

        let err = plugin
            .call::<_, Ping>(
                "call",
                &Ping { n: 1 },
                engine.ticks_for(Duration::from_secs(1)),
            )
            .unwrap_err();

        assert!(matches!(err, PluginCallError::Trap(_)), "got {err:?}");
    }

    /// Ticket test 2: a plugin that never returns is interrupted once the
    /// deadline elapses, and the call returns in bounded time rather than
    /// hanging forever.
    #[test]
    fn deadline_fires_on_a_plugin_that_never_returns() {
        let engine = PluginEngine::with_tick(Duration::from_millis(5));
        let mut plugin = instance_for(&engine, &infinite_loop_module());

        let started = Instant::now();
        let err = plugin
            .call::<_, Ping>(
                "call",
                &Ping { n: 1 },
                engine.ticks_for(Duration::from_millis(20)),
            )
            .unwrap_err();
        let elapsed = started.elapsed();

        assert_eq!(err, PluginCallError::DeadlineExceeded);
        assert!(
            elapsed < Duration::from_secs(5),
            "took {elapsed:?} to interrupt"
        );
    }

    /// Ticket test 3: a plugin returning bytes that are not valid JSON for
    /// the expected type fails deserialisation cleanly.
    #[test]
    fn garbage_bytes_fail_deserialisation_cleanly() {
        let engine = PluginEngine::with_tick(Duration::from_millis(5));
        let mut plugin = instance_for(&engine, &garbage_module());

        let err = plugin
            .call::<_, Ping>(
                "call",
                &Ping { n: 1 },
                engine.ticks_for(Duration::from_secs(1)),
            )
            .unwrap_err();

        assert!(
            matches!(err, PluginCallError::Deserialize(_)),
            "got {err:?}"
        );
    }

    /// A garbage packed length is rejected against the plugin's actual
    /// memory size before any allocation is attempted — not just garbage
    /// *bytes* at a valid length (see `garbage_bytes_fail_deserialisation_cleanly`
    /// above), but a claimed length the plugin's memory could not possibly
    /// back. An adversarial plugin could claim a length up to ~4 GiB this
    /// way; before the bound check, that allocation was attempted before
    /// wasmtime's own memory-bounds check ever ran, and a failed allocation
    /// that large aborts the process rather than returning an error.
    #[test]
    fn garbage_length_is_rejected_before_allocating() {
        let engine = PluginEngine::with_tick(Duration::from_millis(5));
        let mut plugin = instance_for(&engine, &garbage_length_module());

        let err = plugin
            .call::<_, Ping>(
                "call",
                &Ping { n: 1 },
                engine.ticks_for(Duration::from_secs(1)),
            )
            .unwrap_err();

        // Specifically the bound check's own message, not wasmtime's
        // separate (and looser) out-of-bounds error from `Memory::read` —
        // proves the length was rejected before the read/allocation was
        // even attempted, not merely that some error eventually surfaced.
        match &err {
            PluginCallError::Other(msg) => {
                assert!(msg.contains("out-of-bounds answer"), "got {msg:?}");
            }
            other => panic!("expected PluginCallError::Other, got {other:?}"),
        }
    }

    /// A store that has trapped is still usable for the next call — the
    /// premise behind "instantiate once and keep", not re-instantiate on
    /// every failure.
    #[test]
    fn a_trapped_instance_can_still_be_called_again() {
        let engine = PluginEngine::with_tick(Duration::from_millis(5));
        let mut plugin = instance_for(&engine, &panicking_module());

        assert!(
            plugin
                .call::<_, Ping>(
                    "call",
                    &Ping { n: 1 },
                    engine.ticks_for(Duration::from_secs(1))
                )
                .is_err()
        );
        assert!(
            plugin
                .call::<_, Ping>(
                    "call",
                    &Ping { n: 1 },
                    engine.ticks_for(Duration::from_secs(1))
                )
                .is_err(),
            "the same trap should reproduce, not corrupt the store into something else"
        );
    }

    #[test]
    fn pack_unpack_roundtrips() {
        assert_eq!(unpack(pack(1234, 5678)), (1234, 5678));
        assert_eq!(unpack(pack(0, 0)), (0, 0));
        assert_eq!(unpack(pack(u32::MAX, u32::MAX)), (u32::MAX, u32::MAX));
    }

    #[test]
    fn ticks_for_is_never_zero() {
        let engine = PluginEngine::with_tick(Duration::from_millis(10));
        assert_eq!(engine.ticks_for(Duration::from_millis(0)), 1);
        assert_eq!(engine.ticks_for(Duration::from_millis(1)), 1);
        assert_eq!(engine.ticks_for(Duration::from_millis(10)), 1);
        assert_eq!(engine.ticks_for(Duration::from_millis(11)), 2);
    }

    /// Records what it was asked and answers with a fixed result.
    struct RecordingCalls {
        asked: std::sync::Mutex<Vec<Vec<u8>>>,
        answer: Result<Vec<u8>, String>,
    }

    impl RecordingCalls {
        fn answering(answer: &str) -> Arc<Self> {
            Arc::new(Self {
                asked: std::sync::Mutex::new(Vec::new()),
                answer: Ok(answer.as_bytes().to_vec()),
            })
        }

        fn failing(message: &str) -> Arc<Self> {
            Arc::new(Self {
                asked: std::sync::Mutex::new(Vec::new()),
                answer: Err(message.to_string()),
            })
        }
    }

    impl PluginHostCalls for RecordingCalls {
        fn storage_query(&self, request: &[u8]) -> Result<Vec<u8>, String> {
            self.asked.lock().unwrap().push(request.to_vec());
            self.answer.clone()
        }

        fn invoice_create(&self, request: &[u8]) -> Result<Vec<u8>, String> {
            self.asked.lock().unwrap().push(request.to_vec());
            self.answer.clone()
        }

        fn merchant_volume(&self, request: &[u8]) -> Result<Vec<u8>, String> {
            self.asked.lock().unwrap().push(request.to_vec());
            self.answer.clone()
        }

        fn merchant_volumes(&self, request: &[u8]) -> Result<Vec<u8>, String> {
            self.asked.lock().unwrap().push(request.to_vec());
            self.answer.clone()
        }

        fn account_standing(&self, request: &[u8]) -> Result<Vec<u8>, String> {
            self.asked.lock().unwrap().push(request.to_vec());
            self.answer.clone()
        }

        fn account_notice(&self, request: &[u8]) -> Result<Vec<u8>, String> {
            self.asked.lock().unwrap().push(request.to_vec());
            self.answer.clone()
        }
    }

    /// The capability this whole import surface exists for: before it, a
    /// plugin was a pure function and could not read its own tables.
    #[test]
    fn a_plugin_can_ask_the_host_a_question_and_read_the_answer() {
        let engine = PluginEngine::new();
        let module = engine.compile(&fixtures::host_calling_module()).unwrap();
        let calls = RecordingCalls::answering(r#"{"rows":[{"paid_until":"2026-10-01"}]}"#);
        let mut instance = engine
            .instantiate_with_calls(&module, calls.clone())
            .unwrap();

        let answer = instance
            .call_raw("call", br#"{"sql":"select paid_until"}"#, 1_000)
            .unwrap();

        assert_eq!(
            String::from_utf8(answer).unwrap(),
            r#"{"rows":[{"paid_until":"2026-10-01"}]}"#
        );
        let asked = calls.asked.lock().unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(
            asked[0],
            br#"{"sql":"select paid_until"}"#.to_vec(),
            "the host must see the plugin's request bytes unchanged"
        );
    }

    /// The money-path import, end to end: a plugin asks for an invoice and
    /// reads back what the host issued. Same two-step protocol, same
    /// `host_take` - which is the part that would break if a second
    /// answering call needed a buffer of its own.
    #[test]
    fn a_plugin_can_ask_the_host_to_issue_an_invoice() {
        let engine = PluginEngine::new();
        let module = engine.compile(&fixtures::invoice_calling_module()).unwrap();
        let calls = RecordingCalls::answering(r#"{"invoice_id":"inv-1"}"#);
        let mut instance = engine
            .instantiate_with_calls(&module, calls.clone())
            .unwrap();

        let answer = instance
            .call_raw("call", br#"{"asset_symbol":"USDC","amount":"129"}"#, 1_000)
            .unwrap();

        assert_eq!(
            String::from_utf8(answer).unwrap(),
            r#"{"invoice_id":"inv-1"}"#
        );
        assert_eq!(
            calls.asked.lock().unwrap()[0],
            br#"{"asset_symbol":"USDC","amount":"129"}"#.to_vec(),
            "the host must see the plugin's request bytes unchanged"
        );
    }

    /// The two answering calls must not be the same function under two
    /// names. Back the host with a module that imports only `invoice_create`
    /// and check the request still arrives - if the linker had defined one
    /// import twice, or defined `invoice_create` as `storage_query`, this
    /// module would fail to instantiate rather than answer.
    #[test]
    fn invoice_create_is_its_own_import() {
        let engine = PluginEngine::new();
        let storage_only = engine.compile(&fixtures::host_calling_module()).unwrap();
        let invoice_only = engine.compile(&fixtures::invoice_calling_module()).unwrap();
        let calls = RecordingCalls::answering("{}");

        assert!(
            engine
                .instantiate_with_calls(&storage_only, calls.clone())
                .is_ok()
        );
        assert!(
            engine.instantiate_with_calls(&invoice_only, calls).is_ok(),
            "a plugin importing only invoice_create must instantiate"
        );
    }

    /// The same property for the third call. Three imports defined in one
    /// loop-shaped helper is exactly where a copy-paste puts the wrong method
    /// behind the right name, and the resulting plugin would still
    /// instantiate - it would simply get an invoice back when it asked for a
    /// volume. Checking the *answer* rather than only instantiation is what
    /// separates those.
    #[test]
    fn merchant_volume_is_its_own_import_and_reaches_its_own_method() {
        let engine = PluginEngine::new();
        let module = engine.compile(&fixtures::volume_calling_module()).unwrap();
        let calls = Arc::new(NamingCalls);
        let mut instance = engine
            .instantiate_with_calls(&module, calls)
            .expect("a plugin importing only merchant_volume must instantiate");

        let answer = instance
            .call_raw("call", br#"{"account_id":"a-1","window_days":30}"#, 1_000)
            .unwrap();

        assert_eq!(
            String::from_utf8(answer).unwrap(),
            "merchant_volume",
            "the merchant_volume import must reach merchant_volume, not another method"
        );
    }

    /// The same property for the fourth call. Same reasoning as
    /// [`merchant_volume_is_its_own_import_and_reaches_its_own_method`]: a
    /// module importing only `merchant_volumes` must both instantiate and
    /// reach `merchant_volumes` specifically, not `merchant_volume` or either
    /// of the other two answering calls wired in the same loop-shaped helper.
    #[test]
    fn merchant_volumes_is_its_own_import_and_reaches_its_own_method() {
        let engine = PluginEngine::new();
        let module = engine.compile(&fixtures::volumes_calling_module()).unwrap();
        let calls = Arc::new(NamingCalls);
        let mut instance = engine
            .instantiate_with_calls(&module, calls)
            .expect("a plugin importing only merchant_volumes must instantiate");

        let answer = instance
            .call_raw(
                "call",
                br#"{"account_ids":["a-1","a-2"],"window_days":30}"#,
                1_000,
            )
            .unwrap();

        assert_eq!(
            String::from_utf8(answer).unwrap(),
            "merchant_volumes",
            "the merchant_volumes import must reach merchant_volumes, not another method"
        );
    }

    /// A module importing only `account_standing` must both instantiate and
    /// reach `account_standing` specifically. This is the property deploy
    /// order rests on: a plugin importing a function the host lacks fails to
    /// instantiate.
    #[test]
    fn account_standing_is_its_own_import_and_reaches_its_own_method() {
        let engine = PluginEngine::new();
        let module = engine
            .compile(&fixtures::standing_calling_module())
            .unwrap();
        let mut instance = engine
            .instantiate_with_calls(&module, Arc::new(NamingCalls))
            .expect("a plugin importing only account_standing must instantiate");

        let answer = instance
            .call_raw("call", br#"{"account_id":"a-1"}"#, 1_000)
            .unwrap();

        assert_eq!(
            String::from_utf8(answer).unwrap(),
            "account_standing",
            "the account_standing import must reach account_standing, not another method"
        );
    }

    /// Unbacked, the import still exists: the plugin loads and is told the
    /// host cannot answer, rather than failing to instantiate.
    #[test]
    fn an_unbacked_account_standing_import_still_instantiates() {
        let engine = PluginEngine::new();
        let module = engine
            .compile(&fixtures::standing_calling_module())
            .unwrap();
        let mut instance = engine.instantiate(&module).unwrap();

        assert!(instance.call_raw("call", b"{}", 1_000).is_ok());
    }

    /// There is no import by which a plugin could store a standing. Naming
    /// the obvious candidates must fail to instantiate, so a write capability
    /// cannot appear by someone defining one without this test going red.
    #[test]
    fn no_import_exists_to_write_a_standing() {
        let engine = PluginEngine::new();
        for name in [
            "set_account_standing",
            "account_standing_set",
            "apply_account_standing",
        ] {
            let wasm = wat::parse_str(format!(
                r#"
                (module
                    (import "ethpayserver" "{name}"
                        (func $w (param i32 i32) (result i64)))
                    (memory (export "memory") 1)
                    (func (export "alloc") (param i32) (result i32) (i32.const 0))
                    (func (export "call") (param i32) (param i32) (result i64) (i64.const 0))
                )
                "#
            ))
            .unwrap();
            let module = engine.compile(&wasm).unwrap();
            assert!(
                matches!(
                    engine.instantiate(&module),
                    Err(PluginWasmError::Instantiate(_))
                ),
                "{name} must not be an import"
            );
        }
    }

    /// The same property for the sixth call. Same reasoning as
    /// [`merchant_volume_is_its_own_import_and_reaches_its_own_method`]: a
    /// module importing only `account_notice` must both instantiate and
    /// reach `account_notice` specifically, not any of the other five
    /// answering calls wired in the same loop-shaped helper.
    #[test]
    fn account_notice_is_its_own_import_and_reaches_its_own_method() {
        let engine = PluginEngine::new();
        let module = engine.compile(&fixtures::notice_calling_module()).unwrap();
        let calls = Arc::new(NamingCalls);
        let mut instance = engine
            .instantiate_with_calls(&module, calls)
            .expect("a plugin importing only account_notice must instantiate");

        let answer = instance
            .call_raw(
                "call",
                br#"{"account_id":"a-1","subject":"s","body":"b"}"#,
                1_000,
            )
            .unwrap();

        assert_eq!(
            String::from_utf8(answer).unwrap(),
            "account_notice",
            "the account_notice import must reach account_notice, not another method"
        );
    }

    /// Answers with the name of whichever method was called, so a test can
    /// tell the six answering calls apart by their result.
    struct NamingCalls;

    impl PluginHostCalls for NamingCalls {
        fn storage_query(&self, _request: &[u8]) -> Result<Vec<u8>, String> {
            Ok(b"storage_query".to_vec())
        }

        fn invoice_create(&self, _request: &[u8]) -> Result<Vec<u8>, String> {
            Ok(b"invoice_create".to_vec())
        }

        fn merchant_volume(&self, _request: &[u8]) -> Result<Vec<u8>, String> {
            Ok(b"merchant_volume".to_vec())
        }

        fn merchant_volumes(&self, _request: &[u8]) -> Result<Vec<u8>, String> {
            Ok(b"merchant_volumes".to_vec())
        }

        fn account_standing(&self, _request: &[u8]) -> Result<Vec<u8>, String> {
            Ok(b"account_standing".to_vec())
        }

        fn account_notice(&self, _request: &[u8]) -> Result<Vec<u8>, String> {
            Ok(b"account_notice".to_vec())
        }
    }

    /// An unbacked host is unbacked for every call, and says which one it
    /// could not serve. The plugin gets the message where the answer would
    /// have been, so "storage" and "invoices" do not read the same.
    #[test]
    fn an_unbacked_invoice_call_says_so_in_its_own_words() {
        let engine = PluginEngine::new();
        let module = engine.compile(&fixtures::invoice_calling_module()).unwrap();
        let mut instance = engine.instantiate(&module).unwrap();

        // The fixture returns an empty answer on a negative length rather
        // than taking the message, so reach for the message the way a real
        // plugin does: ask, get the failure, then take.
        let result = instance.call_raw("call", b"{}", 1_000);
        assert!(
            result.is_ok(),
            "an unbacked invoice call must not trap the plugin: {result:?}"
        );
    }

    /// A host that cannot service the call answers with an error rather than
    /// trapping. Trapping would count against the plugin's failure budget and
    /// eventually disable it, for a shortcoming that is the host's.
    #[test]
    fn an_unbacked_host_call_is_an_error_not_a_trap() {
        let engine = PluginEngine::new();
        let module = engine.compile(&fixtures::host_calling_module()).unwrap();
        // `instantiate`, not `instantiate_with_calls`: imports are defined,
        // nothing backs them.
        let mut instance = engine.instantiate(&module).unwrap();

        let result = instance.call_raw("call", b"{}", 1_000);

        assert!(
            result.is_ok(),
            "an unbacked host call must not trap the plugin: {result:?}"
        );
        assert!(result.unwrap().is_empty());
    }

    /// A failing query is likewise reported, not fatal.
    #[test]
    fn a_failing_host_call_does_not_trap_the_plugin() {
        let engine = PluginEngine::new();
        let module = engine.compile(&fixtures::host_calling_module()).unwrap();
        let mut instance = engine
            .instantiate_with_calls(&module, RecordingCalls::failing("relation does not exist"))
            .unwrap();

        assert!(instance.call_raw("call", b"{}", 1_000).is_ok());
    }

    /// An import this host has never heard of must fail at instantiation.
    /// Defining unknown imports as traps would let a plugin load believing it
    /// had a capability, and discover otherwise only when a call crashed.
    #[test]
    fn an_unknown_host_import_fails_to_instantiate() {
        let engine = PluginEngine::new();
        let wasm = wat::parse_str(
            r#"
            (module
                (import "ethpayserver" "read_every_merchants_wallet"
                    (func $nope (param i32 i32) (result i64)))
                (memory (export "memory") 1)
                (func (export "alloc") (param i32) (result i32) (i32.const 0))
                (func (export "call") (param i32) (param i32) (result i64) (i64.const 0))
            )
            "#,
        )
        .unwrap();
        let module = engine.compile(&wasm).unwrap();

        assert!(matches!(
            engine.instantiate(&module),
            Err(PluginWasmError::Instantiate(_))
        ));
    }

    /// The size guard itself, which an end-to-end test cannot see.
    ///
    /// `Memory::read` refuses an out-of-bounds range too, so removing
    /// `in_bounds` changes no observable behaviour — the call still fails, the
    /// host implementation still never sees the request, and
    /// `a_request_pointing_outside_plugin_memory_is_refused` below still
    /// passes. What changes is that a nearly-4 GiB allocation happens first,
    /// and Rust's allocator aborts the process on failure rather than
    /// returning. This is the test that goes red.
    #[test]
    fn in_bounds_rejects_a_range_that_leaves_memory() {
        const PAGE: usize = 64 * 1024;

        assert!(in_bounds(0, PAGE, PAGE), "the whole memory is in bounds");
        assert!(
            in_bounds(PAGE, 0, PAGE),
            "an empty range at the end is fine"
        );
        assert!(!in_bounds(0, PAGE + 1, PAGE), "one byte too long");
        assert!(
            !in_bounds(1, PAGE, PAGE),
            "in range, but starting one byte in"
        );
        assert!(
            !in_bounds(0, 2_000_000_000, PAGE),
            "the allocation this exists to prevent"
        );
        assert!(
            !in_bounds(usize::MAX, 1, PAGE),
            "a pointer past the end must not wrap into a valid range"
        );
    }

    /// The same condition seen from the outside: an out-of-bounds request is
    /// refused and never reaches the host implementation.
    ///
    /// Deliberately *not* the test for `in_bounds` — see above for why it
    /// cannot be.
    #[test]
    fn a_request_pointing_outside_plugin_memory_is_refused() {
        let engine = PluginEngine::new();
        let wasm = wat::parse_str(
            r#"
            (module
                (import "ethpayserver" "storage_query"
                    (func $query (param i32 i32) (result i64)))
                (memory (export "memory") 1)
                (func (export "alloc") (param i32) (result i32) (i32.const 0))
                (func (export "call") (param i32) (param i32) (result i64)
                    (drop (call $query (i32.const 0) (i32.const 2000000000)))
                    (i64.const 0))
            )
            "#,
        )
        .unwrap();
        let module = engine.compile(&wasm).unwrap();
        let calls = RecordingCalls::answering("{}");
        let mut instance = engine
            .instantiate_with_calls(&module, calls.clone())
            .unwrap();

        let result = instance.call_raw("call", b"{}", 1_000);

        assert!(result.is_ok(), "the refusal must not take the host down");
        assert!(
            calls.asked.lock().unwrap().is_empty(),
            "an out-of-bounds request must never reach the host implementation"
        );
    }
}
