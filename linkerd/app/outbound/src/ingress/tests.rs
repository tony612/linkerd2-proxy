mod http {
    use crate::{
        http::Endpoint,
        logical::ConcreteAddr,
        test_util::{
            support::{connect::Connect, http_util, profile, resolver},
            *,
        },
        Config, Outbound,
    };
    use hyper::{client::conn::Builder as ClientBuilder, Body, Request, Response};
    use linkerd_app_core::{
        io,
        proxy::core::Resolve,
        svc::{self, NewService},
        tls,
        transport::orig_dst,
        Addr, Error, NameAddr, ProxyRuntime,
    };
    use std::{net::SocketAddr, str::FromStr};
    use tracing::Instrument;

    fn build_ingress<I, R>(
        rt: ProxyRuntime,
        profiles: resolver::Profiles,
        resolver: R,
        connect: Connect<Endpoint>,
    ) -> impl svc::NewService<
        orig_dst::Addrs,
        Service = impl tower::Service<
            I,
            Response = (),
            Error = impl Into<linkerd_app_core::Error>,
            Future = impl Send + 'static,
        > + Send
                      + 'static,
    > + Send
           + 'static
    where
        I: io::AsyncRead + io::AsyncWrite + io::PeerAddr + std::fmt::Debug + Unpin + Send + 'static,
        R: Resolve<ConcreteAddr, Endpoint = resolver::Metadata, Error = Error>
            + Unpin
            + Clone
            + Send
            + Sync
            + 'static,
        R::Resolution: Send,
        R::Future: Send + Unpin,
    {
        use linkerd_app_core::AddrMatch;
        let cfg = Config {
            ingress_mode: true,
            allow_discovery: AddrMatch::new(
                Some("cluster.local.".parse().unwrap()),
                Some(IpNet::from_str("0.0.0.0/0").unwrap()),
            ),
            ..default_config()
        };
        Outbound::new(cfg, rt).into_ingress_with(
            resolver,
            profiles,
            connect,
            support::connect::no_raw_tcp(),
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn meshed_dst_override() {
        let _trace = support::trace_init();

        let ep1 = SocketAddr::new([10, 0, 0, 41].into(), 5550);
        let id = tls::ServerId::from_str("foo.ns1.serviceaccount.identity.linkerd.cluster.local")
            .expect("hostname is invalid");
        let svc_addr = NameAddr::from_str("foo.ns1.svc.cluster.local:5550").unwrap();
        let meta = support::resolver::Metadata::new(
            Default::default(),
            support::resolver::ProtocolHint::Http2,
            None,
            Some(id.clone()),
            None,
        );

        // Pretend the upstream is a proxy that supports proto upgrades...
        let mut server_settings = hyper::server::conn::Http::new();
        server_settings.http2_only(true);
        let connect = support::connect().endpoint_fn_boxed(ep1, hello_server(server_settings));

        let profiles = profile::resolver().profile(
            Addr::from(svc_addr.clone()),
            profile::Profile {
                addr: Some(svc_addr.clone().into()),
                ..Default::default()
            },
        );

        let resolver = support::resolver::<support::resolver::Metadata>();
        let mut dst = resolver.endpoint_tx(svc_addr);
        dst.add(Some((ep1, meta.clone())))
            .expect("still listening to resolution");

        // Build the ingress-mode outbound server
        let (rt, _shutdown) = runtime();
        let server = build_ingress(rt, profiles, resolver, connect).new_service(addrs(ep1));
        let (mut client, bg) =
            http_util::connect_and_accept(&mut ClientBuilder::new(), server).await;
        let req = Request::get("http://example.com/")
            .header("l5d-dst-override", "foo.ns1.svc.cluster.local:5550")
            .body(Default::default())
            .expect("request should be valid");
        let rsp = http_util::http_request(&mut client, req).await;
        assert_eq!(rsp.status(), http::StatusCode::OK);
        let body = http_util::body_to_string(rsp.into_body()).await;
        assert_eq!(body, "Hello world!");

        drop(client);
        bg.await.expect("background task failed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn meshed_profile_endpoint_override() {
        // Note that this scenario should never actually happen, but it's nice
        // to know what we'd do if it did.
        let _trace = support::trace_init();

        let ep1 = SocketAddr::new([10, 0, 0, 41].into(), 5550);
        let ep2 = SocketAddr::new([10, 0, 0, 42].into(), 5550);
        let id = tls::ServerId::from_str("foo.ns1.serviceaccount.identity.linkerd.cluster.local")
            .expect("hostname is invalid");
        let svc_addr = NameAddr::from_str("foo.ns1.svc.cluster.local:5550").unwrap();
        let meta = support::resolver::Metadata::new(
            Default::default(),
            support::resolver::ProtocolHint::Http2,
            None,
            Some(id.clone()),
            None,
        );

        // Pretend the upstream is a proxy that supports proto upgrades...
        let mut server_settings = hyper::server::conn::Http::new();
        server_settings.http2_only(true);
        let connect = support::connect().endpoint_fn_boxed(ep2, hello_server(server_settings));

        let profiles = profile::resolver().profile(
            Addr::from(svc_addr.clone()),
            profile::Profile {
                endpoint: Some((ep2, meta)),
                ..Default::default()
            },
        );

        let resolver = support::resolver::no_destinations();

        // Build the ingress-mode outbound server
        let (rt, _shutdown) = runtime();
        let server = build_ingress(rt, profiles, resolver, connect).new_service(addrs(ep1));
        let (mut client, bg) =
            http_util::connect_and_accept(&mut ClientBuilder::new(), server).await;
        let req = Request::get("http://example.com/")
            .header("l5d-dst-override", "foo.ns1.svc.cluster.local:5550")
            .body(Default::default())
            .expect("request should be valid");
        let rsp = http_util::http_request(&mut client, req).await;
        assert_eq!(rsp.status(), http::StatusCode::OK);
        let body = http_util::body_to_string(rsp.into_body()).await;
        assert_eq!(body, "Hello world!");

        drop(client);
        bg.await.expect("background task failed");
    }

    #[tracing::instrument]
    fn hello_server(
        http: hyper::server::conn::Http,
    ) -> impl Fn(Endpoint) -> Result<io::BoxedIo, Error> {
        move |endpoint| {
            let span = tracing::info_span!("hello_server", ?endpoint);
            let _e = span.enter();
            tracing::info!("mock connecting");
            let (client_io, server_io) = support::io::duplex(4096);
            let hello_svc = hyper::service::service_fn(|request: Request<Body>| async move {
                tracing::info!(?request);
                Ok::<_, Error>(Response::new(Body::from("Hello world!")))
            });
            tokio::spawn(
                http.serve_connection(server_io, hello_svc)
                    .in_current_span(),
            );
            Ok(io::BoxedIo::new(client_io))
        }
    }
}
