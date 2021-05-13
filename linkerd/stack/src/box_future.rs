use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// A middleware that boxes *just* the response future from an inner service,
/// without erasing the service's type (and its trait impls, such as `Clone`).
///
/// This is primarily useful when a service's `Future` type is not `Unpin` and
/// must be boxed.
#[derive(Copy, Clone, Debug)]
pub struct BoxFuture<T>(T);

#[derive(Copy, Debug)]
pub struct BoxFutureLayer<T>(std::marker::PhantomData<fn(T)>);

impl<T> BoxFuture<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    pub fn layer() -> BoxFutureLayer<T> {
        BoxFutureLayer(std::marker::PhantomData)
    }
}

impl<T, R> tower::Service<R> for BoxFuture<T>
where
    T: tower::Service<R>,
    T::Future: Send + 'static,
{
    type Response = T::Response;
    type Error = T::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    #[inline]
    fn call(&mut self, req: R) -> Self::Future {
        Box::pin(self.0.call(req))
    }
}

// === impl BoxFutureLayer ===

impl<T> tower::Layer<T> for BoxFutureLayer<T> {
    type Service = BoxFuture<T>;
    fn layer(&self, svc: T) -> Self::Service {
        BoxFuture(svc)
    }
}

impl<T> Clone for BoxFutureLayer<T> {
    fn clone(&self) -> Self {
        Self(std::marker::PhantomData)
    }
}
