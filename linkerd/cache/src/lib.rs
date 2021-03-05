#![deny(warnings, rust_2018_idioms)]

use futures::prelude::*;
use linkerd_stack::{layer, NewService};
use parking_lot::RwLock;
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt,
    hash::Hash,
    sync::{Arc, Weak},
    task::{Context, Poll},
};
use tokio::{sync::Notify, time};
use tracing::{debug, debug_span, instrument::Instrument, trace};

#[derive(Clone)]
pub struct Cache<T, N>
where
    T: Eq + Hash,
    N: NewService<T>,
{
    inner: N,
    services: Arc<Services<T, N::Service>>,
    idle: time::Duration,
}

#[derive(Clone, Debug)]
pub struct Cached<S>
where
    S: Send + Sync + 'static,
{
    inner: S,
    // Notifies entry's eviction task that a drop has occurred.
    handle: Arc<Notify>,
}

type Services<T, S> = RwLock<HashMap<T, (S, Weak<Notify>)>>;

// === impl Cache ===

impl<T, N> Cache<T, N>
where
    T: Clone + std::fmt::Debug + Eq + Hash + Send + Sync + 'static,
    N: NewService<T> + 'static,
    N::Service: Send + Sync + 'static,
{
    pub fn layer(idle: time::Duration) -> impl layer::Layer<N, Service = Self> + Clone {
        layer::mk(move |inner| Self::new(idle, inner))
    }

    fn new(idle: time::Duration, inner: N) -> Self {
        let services = Arc::new(Services::default());
        Self {
            inner,
            services,
            idle,
        }
    }

    fn spawn_idle(
        target: T,
        idle: time::Duration,
        cache: &Arc<Services<T, N::Service>>,
    ) -> Arc<Notify> {
        // Spawn a background task that holds the handle. Every time the handle
        // is notified, it resets the idle timeout. Every time teh idle timeout
        // expires, the handle is checked and the service is dropped if there
        // are no active handles.
        let handle = Arc::new(Notify::new());
        let span = debug_span!(
            "evict",
            ?target,
            handle = ?Ptr(&handle)
        );
        tokio::spawn(
            Self::evict(target, idle, handle.clone(), Arc::downgrade(&cache)).instrument(span),
        );
        handle
    }

    async fn evict(
        target: T,
        idle: time::Duration,
        mut reset: Arc<Notify>,
        cache: Weak<Services<T, N::Service>>,
    ) {
        // Wait for the handle to be notified before starting to track idleness.
        reset.notified().await;
        debug!("Awaiting idleness");

        // Wait for either the reset to be notified or the idle timeout to
        // elapse.
        loop {
            futures::select_biased! {
                // If the reset was notified, restart the timer.
                _ = reset.notified().fuse() => {
                    trace!("Reset");
                }
                _ = time::sleep(idle).fuse() => match cache.upgrade() {
                    Some(cache) => match Arc::try_unwrap(reset) {
                        // If this is the last reference to the handle after the
                        // idle timeout, remove the cache entry.
                        Ok(_) => {
                            let removed = cache.write().remove(&target).is_some();
                            debug_assert!(removed, "Cache item must exist: {:?}", target);
                            debug!("Cache entry dropped");
                            return;
                        }
                        // Otherwise, another handle has been acquired, so
                        // restore our reset reference for the next iteration.
                        Err(r) => {
                            trace!(refs = Arc::strong_count(&r), "The handle is still active");
                            reset = r;
                        }
                    },
                    None => {
                        trace!("Cache already dropped");
                        return;
                    }
                },
            }
        }
    }
}

impl<T, N> NewService<T> for Cache<T, N>
where
    T: Clone + std::fmt::Debug + Eq + Hash + Send + Sync + 'static,
    N: NewService<T> + 'static,
    N::Service: Clone + Send + Sync + 'static,
{
    type Service = Cached<N::Service>;

    fn new_service(&mut self, target: T) -> Cached<N::Service> {
        // We expect the item to be available in most cases, so initially obtain
        // only a read lock.
        if let Some((svc, weak)) = self.services.read().get(&target) {
            if let Some(handle) = weak.upgrade() {
                trace!(
                    ?target,
                    handle = ?Ptr(&handle),
                    refs = Arc::strong_count(&handle),
                    "Using cached service"
                );
                return Cached {
                    inner: svc.clone(),
                    handle,
                };
            }
        }

        // Otherwise, obtain a write lock to insert a new service.
        match self.services.write().entry(target.clone()) {
            Entry::Occupied(mut entry) => {
                // Another thread raced us to create a service for this target.
                // Try to use it.
                let (svc, weak) = entry.get();
                match weak.upgrade() {
                    Some(handle) => {
                        trace!(
                            ?target,
                            handle = ?Ptr(&handle),
                            refs = Arc::strong_count(&handle),
                            raced = true,
                            "Using cached service"
                        );
                        Cached {
                            inner: svc.clone(),
                            handle,
                        }
                    }
                    None => {
                        let handle = Self::spawn_idle(target.clone(), self.idle, &self.services);
                        debug!(
                            ?target,
                            handle.old = ?Ptr(&weak),
                            handle.new = ?Ptr(&handle),
                            "Replacing defunct service"
                        );
                        let inner = self.inner.new_service(target);
                        entry.insert((inner.clone(), Arc::downgrade(&handle)));
                        Cached { inner, handle }
                    }
                }
            }
            Entry::Vacant(entry) => {
                let handle = Self::spawn_idle(target.clone(), self.idle, &self.services);
                debug!(?target, handle = ?Ptr(&handle), "Caching new service");
                let inner = self.inner.new_service(target);
                entry.insert((inner.clone(), Arc::downgrade(&handle)));
                Cached { inner, handle }
            }
        }
    }
}

// === impl Cached ===

impl<Req, S> tower::Service<Req> for Cached<S>
where
    S: tower::Service<Req> + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    #[inline]
    fn call(&mut self, req: Req) -> Self::Future {
        self.inner.call(req)
    }
}

impl<S> Drop for Cached<S>
where
    S: Send + Sync + 'static,
{
    fn drop(&mut self) {
        trace!(
            handle = ?Ptr(&self.handle),
            refs = Arc::strong_count(&self.handle),
            "Dropping cached service",
        );
        self.handle.notify_one();
    }
}

struct Ptr<'a, T>(&'a T);

impl<'a, T> fmt::Debug for Ptr<'a, T>
where
    T: fmt::Pointer,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Pointer::fmt(self.0, f)
    }
}

#[cfg(test)]
#[tokio::test]
async fn test_idle_retain() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .try_init();
    time::pause();

    let idle = time::Duration::from_secs(10);
    let cache = Arc::new(Services::default());

    let handle = Cache::<(), fn(()) -> ()>::spawn_idle((), idle, &cache);
    cache.write().insert((), ((), Arc::downgrade(&handle)));
    let c0 = Cached { inner: (), handle };

    let handle = Arc::downgrade(&c0.handle);

    // Let an idle timeout elapse and ensured the held service has not been
    // evicted.
    time::sleep(idle * 2).await;
    assert!(handle.upgrade().is_some());
    assert!(cache.read().contains_key(&()));

    // Drop the original cached instance and elapse only half of the idle
    // timeout.
    drop(c0);
    time::sleep(time::Duration::from_secs(5)).await;
    assert!(handle.upgrade().is_some());
    assert!(cache.read().contains_key(&()));

    // Ensure that the handle hasn't been dropped yet and revive it to create a
    // new cached instance.
    let c1 = Cached {
        inner: (),
        // Retain the handle from the first instance.
        handle: handle.upgrade().unwrap(),
    };

    // Drop the new cache instance. Wait the remainder of the first idle timeout
    // and esnure that the handle is still retained.
    drop(c1);
    time::sleep(time::Duration::from_secs(5)).await;
    assert!(handle.upgrade().is_some());
    assert!(cache.read().contains_key(&()));

    // Wait the remainder of the second idle timeout and esnure the handle has
    // been dropped.
    time::sleep(time::Duration::from_secs(5)).await;
    assert!(handle.upgrade().is_none());
    assert!(!cache.read().contains_key(&()));
}
