//! Outbound groups (sing-box `protocol/group`): `selector`, which goes
//! through the member the user picked, and `urltest`, which goes through the
//! member with the lowest URL test delay.
//!
//! The router dials a group's selection itself (it resolves the chain and
//! attaches the connection to every group in it); a group dials only when
//! another part of rust-box uses it as a detour.

mod interrupt;
#[cfg(test)]
mod tests;
mod urltest_client;

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use rb_adapter::{
    real_tag, Attachment, BoxStream, HistoryStorage, InboundContext, Interrupt, Network, Outbound, OutboundGroup,
    SharedPacketConn, UrlTestHistory,
};
use rb_cachefile::CacheFile;
use rb_certificate::Store;
use rb_config::{SelectorOutbound, UrlTestOutbound};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{debug, error};

pub use interrupt::InterruptGroup;
pub use urltest_client::{url_test, DEFAULT_URL, TCP_TIMEOUT};

/// sing-box `C.DefaultURLTestInterval`.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(3 * 60);
/// sing-box `C.DefaultURLTestIdleTimeout`.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// The default tolerance in milliseconds.
pub const DEFAULT_TOLERANCE: u16 = 50;
/// How many outbounds one URL test checks at once.
const CONCURRENCY: usize = 10;

const TCP_UDP: &[Network] = &[Network::Tcp, Network::Udp];
const TCP: &[Network] = &[Network::Tcp];
const UDP: &[Network] = &[Network::Udp];
const NONE: &[Network] = &[];

/// A static slice with the same networks, so a group can report its
/// selection's networks.
fn networks_of(outbound: &Arc<dyn Outbound>) -> &'static [Network] {
    let networks = outbound.networks();
    match (networks.contains(&Network::Tcp), networks.contains(&Network::Udp)) {
        (true, true) => TCP_UDP,
        (true, false) => TCP,
        (false, true) => UDP,
        (false, false) => NONE,
    }
}

fn missing_outbound() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "missing supported outbound")
}

/// Finds an outbound by tag (the outbound manager).
pub type Lookup<'a> = &'a dyn Fn(&str) -> Option<Arc<dyn Outbound>>;

/// What the groups share: the cache file, the URL test history and the
/// certificate store the URL tests verify with.
#[derive(Clone)]
pub struct GroupContext {
    pub cache_file: Option<Arc<CacheFile>>,
    pub history: Arc<HistoryStorage>,
    pub store: Arc<Store>,
}

/// The `selector` outbound.
pub struct Selector {
    tag: String,
    tags: Vec<String>,
    default_tag: String,
    interrupt_external: bool,
    context: GroupContext,
    outbounds: OnceLock<HashMap<String, Arc<dyn Outbound>>>,
    selected: RwLock<Option<Arc<dyn Outbound>>>,
    interrupts: InterruptGroup,
}

impl Selector {
    /// `NewSelector` (the tags were checked with the configuration).
    pub fn new(options: &SelectorOutbound, context: GroupContext) -> Self {
        Selector {
            tag: options.tag.clone(),
            tags: options.outbounds.clone(),
            default_tag: options.default.clone(),
            interrupt_external: options.interrupt_exist_connections,
            context,
            outbounds: OnceLock::new(),
            selected: RwLock::new(None),
            interrupts: InterruptGroup::new(),
        }
    }

    /// The start stage: finds the members, then selects the one the cache
    /// file saved, else `default`, else the first.
    pub fn start(&self, lookup: Lookup<'_>) -> Result<(), String> {
        let mut outbounds = HashMap::new();
        for (index, tag) in self.tags.iter().enumerate() {
            let outbound = lookup(tag).ok_or_else(|| format!("outbound {index} not found: {tag}"))?;
            outbounds.insert(tag.clone(), outbound);
        }
        let outbounds = self.outbounds.get_or_init(|| outbounds);
        if !self.tag.is_empty() {
            if let Some(cache_file) = &self.context.cache_file {
                let saved = cache_file.load_selected(&self.tag);
                if let Some(outbound) = outbounds.get(&saved) {
                    *self.selected.write().unwrap() = Some(outbound.clone());
                    return Ok(());
                }
            }
        }
        let selected = if !self.default_tag.is_empty() {
            outbounds
                .get(&self.default_tag)
                .ok_or_else(|| format!("default outbound not found: {}", self.default_tag))?
        } else {
            &outbounds[&self.tags[0]]
        };
        *self.selected.write().unwrap() = Some(selected.clone());
        Ok(())
    }

    /// The selected member, before the start none.
    pub fn now(&self) -> Option<Arc<dyn Outbound>> {
        self.selected.read().unwrap().clone()
    }

    /// The members, once started.
    pub fn members(&self) -> Vec<Arc<dyn Outbound>> {
        let Some(outbounds) = self.outbounds.get() else { return Vec::new() };
        self.tags.iter().filter_map(|tag| outbounds.get(tag).cloned()).collect()
    }

    /// `SelectOutbound`: false when `tag` is not a member. A change is
    /// saved to the cache file and interrupts the attached connections.
    pub fn select_outbound(&self, tag: &str) -> bool {
        let Some(outbound) = self.outbounds.get().and_then(|outbounds| outbounds.get(tag)).cloned() else {
            return false;
        };
        {
            let mut selected = self.selected.write().unwrap();
            if selected.as_ref().is_some_and(|current| Arc::ptr_eq(current, &outbound)) {
                return true;
            }
            *selected = Some(outbound);
        }
        if !self.tag.is_empty() {
            if let Some(cache_file) = &self.context.cache_file {
                if let Err(error) = cache_file.store_selected(&self.tag, tag) {
                    error!("outbound/selector[{}]: store selected: {error}", self.tag);
                }
            }
        }
        self.interrupts.interrupt(self.interrupt_external);
        true
    }

    /// The attached connections (for tests).
    pub fn attached(&self) -> usize {
        self.interrupts.len()
    }
}

#[async_trait]
impl Outbound for Selector {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "selector"
    }

    fn networks(&self) -> &[Network] {
        match self.now() {
            Some(selected) => networks_of(&selected),
            None => TCP_UDP,
        }
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        let selected = self.now().ok_or_else(missing_outbound)?;
        let stream = selected.dial_tcp(context).await?;
        Ok(self.interrupts.wrap_stream(stream))
    }

    async fn listen_packet(&self, context: &InboundContext) -> io::Result<SharedPacketConn> {
        let selected = self.now().ok_or_else(missing_outbound)?;
        let conn = selected.listen_packet(context).await?;
        Ok(self.interrupts.wrap_packet_conn(conn))
    }

    fn group(&self) -> Option<&dyn OutboundGroup> {
        Some(self)
    }
}

impl OutboundGroup for Selector {
    fn all(&self) -> Vec<String> {
        self.tags.clone()
    }

    fn selected(&self, _network: Network) -> Option<Arc<dyn Outbound>> {
        self.now()
    }

    fn attach(&self, interrupt: Arc<Interrupt>) -> Attachment {
        self.interrupts.add(&interrupt)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct Ticker {
    id: u64,
    task: tokio::task::JoinHandle<()>,
}

/// The state of a URL test group (sing-box `URLTestGroup`).
struct UrlTestGroup {
    tag: String,
    outbounds: Vec<Arc<dyn Outbound>>,
    link: String,
    interval: Duration,
    tolerance: u16,
    idle_timeout: Duration,
    context: GroupContext,
    interrupt_external: bool,
    checking: AtomicBool,
    selected_tcp: RwLock<Option<Arc<dyn Outbound>>>,
    selected_udp: RwLock<Option<Arc<dyn Outbound>>>,
    interrupts: InterruptGroup,
    /// Serializes [`UrlTestGroup::perform_update_check`].
    update: Mutex<()>,
    ticker: Mutex<Option<Ticker>>,
    next_ticker: Mutex<u64>,
    started: AtomicBool,
    closed: AtomicBool,
    last_active: Mutex<Instant>,
}

/// Outbounds as the batch tests them.
enum Member {
    UrlTest(Arc<UrlTestGroup>),
    Selector(Vec<Arc<dyn Outbound>>),
    Plain(Arc<dyn Outbound>),
}

fn classify(outbound: &Arc<dyn Outbound>) -> Member {
    if let Some(group) = outbound.group() {
        if let Some(urltest) = group.as_any().downcast_ref::<UrlTest>() {
            if let Some(state) = urltest.state.get() {
                return Member::UrlTest(state.clone());
            }
            return Member::Selector(Vec::new());
        }
        if let Some(selector) = group.as_any().downcast_ref::<Selector>() {
            return Member::Selector(selector.members());
        }
    }
    Member::Plain(outbound.clone())
}

/// One URL test round over a set of outbounds (`urlTestBatch`).
struct Batch {
    history: Arc<HistoryStorage>,
    store: Arc<Store>,
    link: String,
    interval: Duration,
    force: bool,
    checked: Vec<String>,
    groups: Vec<Arc<dyn Outbound>>,
    tasks: JoinSet<HashMap<String, u16>>,
    semaphore: Arc<Semaphore>,
}

impl Batch {
    fn test(&mut self, outbounds: &[Arc<dyn Outbound>]) {
        for outbound in outbounds {
            let tag = outbound.tag().to_string();
            if self.checked.contains(&tag) {
                continue;
            }
            match classify(outbound) {
                Member::UrlTest(group) => {
                    self.checked.push(tag);
                    self.groups.push(outbound.clone());
                    let force = self.force;
                    let semaphore = self.semaphore.clone();
                    self.tasks.spawn(async move {
                        let _permit = semaphore.acquire_owned().await;
                        group.url_test(force).await
                    });
                }
                Member::Selector(members) => {
                    self.checked.push(tag);
                    self.groups.push(outbound.clone());
                    self.test(&members);
                }
                Member::Plain(outbound) => {
                    let history = self.history.load(&tag);
                    let fresh = history.is_some_and(|history| {
                        SystemTime::now().duration_since(history.time).unwrap_or_default() < self.interval
                    });
                    if !self.force && fresh {
                        continue;
                    }
                    self.checked.push(tag.clone());
                    let history = self.history.clone();
                    let store = self.store.clone();
                    let link = self.link.clone();
                    let semaphore = self.semaphore.clone();
                    self.tasks.spawn(async move {
                        let _permit = semaphore.acquire_owned().await;
                        let mut result = HashMap::new();
                        match url_test(&link, &outbound, &store).await {
                            Ok(delay) => {
                                debug!("outbound {tag} available: {delay}ms");
                                history.store(&tag, UrlTestHistory { time: SystemTime::now(), delay });
                                result.insert(tag, delay);
                            }
                            Err(error) => {
                                debug!("outbound {tag} unavailable: {error}");
                                history.delete(&tag);
                            }
                        }
                        result
                    });
                }
            }
        }
    }
}

/// sing-box `URLTestOutbounds`: tests the outbounds (through nested groups),
/// skipping those tested within `interval` unless `force`, and returns the
/// delays, the groups' as their TCP selection's.
pub async fn url_test_outbounds(
    outbounds: &[Arc<dyn Outbound>],
    link: &str,
    interval: Duration,
    force: bool,
    history: &Arc<HistoryStorage>,
    store: &Arc<Store>,
) -> HashMap<String, u16> {
    let mut batch = Batch {
        history: history.clone(),
        store: store.clone(),
        link: link.to_string(),
        interval,
        force,
        checked: Vec::new(),
        groups: Vec::new(),
        tasks: JoinSet::new(),
        semaphore: Arc::new(Semaphore::new(CONCURRENCY)),
    };
    batch.test(outbounds);
    let mut result = HashMap::new();
    while let Some(done) = batch.tasks.join_next().await {
        if let Ok(done) = done {
            result.extend(done);
        }
    }
    for group in &batch.groups {
        if let Some(history) = history.load(&real_tag(group, Network::Tcp)) {
            result.insert(group.tag().to_string(), history.delay);
        }
    }
    result
}

impl UrlTestGroup {
    fn selected_for(&self, network: Network) -> Option<Arc<dyn Outbound>> {
        match network {
            Network::Tcp => self.selected_tcp.read().unwrap().clone(),
            Network::Udp => self.selected_udp.read().unwrap().clone(),
        }
    }

    /// `Select`: the member with the lowest delay, keeping the current one
    /// unless another beats it by more than the tolerance; without results
    /// the first member for the network (and false).
    fn select(&self, network: Network) -> (Option<Arc<dyn Outbound>>, bool) {
        let history = &self.context.history;
        let mut min_delay = 0u16;
        let mut min_outbound = None;
        if let Some(current) = self.selected_for(network) {
            if let Some(entry) = history.load(&real_tag(&current, network)) {
                min_delay = entry.delay;
                min_outbound = Some(current);
            }
        }
        for outbound in &self.outbounds {
            if !outbound.networks().contains(&network) {
                continue;
            }
            let Some(entry) = history.load(&real_tag(outbound, network)) else { continue };
            if min_delay == 0 || min_delay > entry.delay.wrapping_add(self.tolerance) {
                min_delay = entry.delay;
                min_outbound = Some(outbound.clone());
            }
        }
        match min_outbound {
            Some(outbound) => (Some(outbound), true),
            None => (self.outbounds.iter().find(|outbound| outbound.networks().contains(&network)).cloned(), false),
        }
    }

    /// `performUpdateCheck`: adopts the new selections and interrupts the
    /// attached connections when one changed.
    fn perform_update_check(&self) {
        let _guard = self.update.lock().unwrap();
        let mut updated = false;
        for network in [Network::Tcp, Network::Udp] {
            let (outbound, exists) = self.select(network);
            let Some(outbound) = outbound else { continue };
            let slot = match network {
                Network::Tcp => &self.selected_tcp,
                Network::Udp => &self.selected_udp,
            };
            let mut current = slot.write().unwrap();
            let change = match current.as_ref() {
                None => true,
                Some(current) => exists && !Arc::ptr_eq(current, &outbound),
            };
            if change {
                updated |= current.is_some();
                *current = Some(outbound);
            }
        }
        if updated {
            self.interrupts.interrupt(self.interrupt_external);
        }
    }

    /// `urlTest`: one round at a time; a round already running answers an
    /// empty result.
    /// Boxed, since a round tests nested URL test groups with this.
    fn url_test(self: Arc<Self>, force: bool) -> Pin<Box<dyn Future<Output = HashMap<String, u16>> + Send>> {
        Box::pin(async move { self.url_test_round(force).await })
    }

    async fn url_test_round(self: Arc<Self>, force: bool) -> HashMap<String, u16> {
        if self.checking.swap(true, Ordering::SeqCst) {
            return HashMap::new();
        }
        let result = url_test_outbounds(
            &self.outbounds,
            &self.link,
            self.interval,
            force,
            &self.context.history,
            &self.context.store,
        )
        .await;
        self.checking.store(false, Ordering::SeqCst);
        if !self.closed.load(Ordering::SeqCst) {
            self.perform_update_check();
        }
        result
    }

    /// `Touch`: marks the group active and starts the periodic check when
    /// it is not running.
    fn touch(self: &Arc<Self>) {
        if !self.started.load(Ordering::SeqCst) || self.closed.load(Ordering::SeqCst) {
            return;
        }
        let mut ticker = self.ticker.lock().unwrap();
        if ticker.is_some() {
            *self.last_active.lock().unwrap() = Instant::now();
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        let id = {
            let mut next = self.next_ticker.lock().unwrap();
            *next += 1;
            *next
        };
        let group = self.clone();
        let task = runtime.spawn(async move { group.loop_check(id).await });
        *ticker = Some(Ticker { id, task });
    }

    /// `loopCheck`: checks every interval until idle for `idle_timeout`.
    async fn loop_check(self: Arc<Self>, id: u64) {
        let elapsed = self.last_active.lock().unwrap().elapsed();
        if elapsed > self.interval {
            *self.last_active.lock().unwrap() = Instant::now();
            self.clone().url_test(false).await;
        }
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + self.interval, self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if self.last_active.lock().unwrap().elapsed() > self.idle_timeout {
                let mut ticker = self.ticker.lock().unwrap();
                if ticker.as_ref().is_some_and(|ticker| ticker.id == id) {
                    *ticker = None;
                }
                return;
            }
            self.clone().url_test(false).await;
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Some(ticker) = self.ticker.lock().unwrap().take() {
            ticker.task.abort();
        }
    }
}

/// The `urltest` outbound.
pub struct UrlTest {
    tag: String,
    tags: Vec<String>,
    options: UrlTestOutbound,
    context: GroupContext,
    state: OnceLock<Arc<UrlTestGroup>>,
}

impl UrlTest {
    /// `NewURLTest` (the tags were checked with the configuration).
    pub fn new(options: &UrlTestOutbound, context: GroupContext) -> Self {
        UrlTest {
            tag: options.tag.clone(),
            tags: options.outbounds.clone(),
            options: options.clone(),
            context,
            state: OnceLock::new(),
        }
    }

    /// The start stage: finds the members (`NewURLTestGroup`).
    pub fn start(&self, lookup: Lookup<'_>) -> Result<(), String> {
        let mut outbounds = Vec::with_capacity(self.tags.len());
        for (index, tag) in self.tags.iter().enumerate() {
            outbounds.push(lookup(tag).ok_or_else(|| format!("outbound {index} not found: {tag}"))?);
        }
        let options = &self.options;
        let interval = if options.interval.0.is_zero() { DEFAULT_INTERVAL } else { options.interval.0 };
        let tolerance = if options.tolerance == 0 { DEFAULT_TOLERANCE } else { options.tolerance };
        let idle_timeout = if options.idle_timeout.0.is_zero() { DEFAULT_IDLE_TIMEOUT } else { options.idle_timeout.0 };
        if interval > idle_timeout {
            return Err("interval must be less or equal than idle_timeout".into());
        }
        let _ = self.state.set(Arc::new(UrlTestGroup {
            tag: self.tag.clone(),
            outbounds,
            link: options.url.clone(),
            interval,
            tolerance,
            idle_timeout,
            context: self.context.clone(),
            interrupt_external: options.interrupt_exist_connections,
            checking: AtomicBool::new(false),
            selected_tcp: RwLock::new(None),
            selected_udp: RwLock::new(None),
            interrupts: InterruptGroup::new(),
            update: Mutex::new(()),
            ticker: Mutex::new(None),
            next_ticker: Mutex::new(0),
            started: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            last_active: Mutex::new(Instant::now()),
        }));
        Ok(())
    }

    /// The started stage (`PostStart`): runs a first check in the
    /// background; the periodic checks start with the first connection.
    pub fn post_start(&self) {
        let Some(group) = self.state.get() else { return };
        group.started.store(true, Ordering::SeqCst);
        *group.last_active.lock().unwrap() = Instant::now();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let group = group.clone();
            runtime.spawn(async move {
                group.url_test(false).await;
            });
        }
    }

    pub fn close(&self) {
        if let Some(group) = self.state.get() {
            group.close();
        }
    }

    /// `URLTest` (the Clash API's group delay): a forced round.
    pub async fn url_test(&self) -> HashMap<String, u16> {
        match self.state.get() {
            Some(group) => group.clone().url_test(true).await,
            None => HashMap::new(),
        }
    }

    /// `CheckOutbounds` with force.
    pub async fn check_outbounds(&self) {
        self.url_test().await;
    }

    /// `PerformUpdateCheck`: re-selects from the current results.
    pub fn perform_update_check(&self) {
        if let Some(group) = self.state.get() {
            group.perform_update_check();
        }
    }

    /// The test URL (empty for the default) and the tolerance.
    pub fn link(&self) -> &str {
        &self.options.url
    }

    /// The members, once started.
    pub fn members(&self) -> Vec<Arc<dyn Outbound>> {
        self.state.get().map(|group| group.outbounds.clone()).unwrap_or_default()
    }

    fn pick(&self, network: Network) -> Option<(Arc<UrlTestGroup>, Arc<dyn Outbound>)> {
        let group = self.state.get()?.clone();
        let outbound = group.selected_for(network).or_else(|| group.select(network).0)?;
        Some((group, outbound))
    }

    /// The attached connections (for tests).
    pub fn attached(&self) -> usize {
        self.state.get().map(|group| group.interrupts.len()).unwrap_or_default()
    }
}

#[async_trait]
impl Outbound for UrlTest {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "urltest"
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        let (group, outbound) = self.pick(Network::Tcp).ok_or_else(missing_outbound)?;
        group.touch();
        match outbound.dial_tcp(context).await {
            Ok(stream) => Ok(group.interrupts.wrap_stream(stream)),
            Err(error) => {
                error!("outbound/urltest[{}]: {error}", group.tag);
                group.context.history.delete(outbound.tag());
                Err(error)
            }
        }
    }

    async fn listen_packet(&self, context: &InboundContext) -> io::Result<SharedPacketConn> {
        let (group, outbound) = self.pick(Network::Udp).ok_or_else(missing_outbound)?;
        group.touch();
        match outbound.listen_packet(context).await {
            Ok(conn) => Ok(group.interrupts.wrap_packet_conn(conn)),
            Err(error) => {
                error!("outbound/urltest[{}]: {error}", group.tag);
                group.context.history.delete(outbound.tag());
                Err(error)
            }
        }
    }

    fn group(&self) -> Option<&dyn OutboundGroup> {
        Some(self)
    }
}

impl OutboundGroup for UrlTest {
    fn all(&self) -> Vec<String> {
        self.tags.clone()
    }

    fn selected(&self, network: Network) -> Option<Arc<dyn Outbound>> {
        self.pick(network).map(|(_, outbound)| outbound)
    }

    fn attach(&self, interrupt: Arc<Interrupt>) -> Attachment {
        match self.state.get() {
            Some(group) => {
                group.touch();
                group.interrupts.add(&interrupt)
            }
            None => Box::new(()),
        }
    }

    fn is_url_test(&self) -> bool {
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
