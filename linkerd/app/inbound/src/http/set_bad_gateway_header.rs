use futures::{ready, Future, TryFuture};
use linkerd_app_core::{
    proxy::http::{Request, Response},
    svc,
};
// use linkerd_error::Error;
use http::HeaderValue;
use pin_project::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

const HEADER_NAME: &str = "l5d-bad-gateway";

#[derive(Clone)]
pub struct SetBadGatewayHeader<S> {
    inner: S,
}

#[pin_project]
pub struct ResponseFuture<F> {
    #[pin]
    inner: F,
}

impl<S> SetBadGatewayHeader<S> {
    pub fn layer() -> impl svc::Layer<S, Service = Self> + Clone {
        svc::layer::mk(move |inner| Self { inner })
    }
}

impl<S, A, B> tower::Service<Request<A>> for SetBadGatewayHeader<S>
where
    S: tower::Service<Request<A>, Response = Response<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<A>) -> Self::Future {
        ResponseFuture {
            inner: self.inner.call(req),
        }
    }
}

impl<F, B> Future for ResponseFuture<F>
where
    F: TryFuture<Ok = Response<B>>,
{
    type Output = Result<F::Ok, F::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let mut response = ready!(this.inner.try_poll(cx))?;
        if response.status().is_server_error() {
            if let Ok(msg) = HeaderValue::from_str(response.status().as_str()) {
                response.headers_mut().insert(HEADER_NAME, msg);
            }
        }
        Poll::Ready(Ok(response))
    }
}
