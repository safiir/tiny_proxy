#![feature(async_closure)]
#![feature(type_ascription)]

use std::{convert::Infallible, net::SocketAddr};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use clap::Parser;
use colored::*;
use hyper::{Body, Request, Response, Server, StatusCode, Uri};
use hyper::client::HttpConnector;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper_proxy::{Intercept, Proxy, ProxyConnector};
use serde_json::json;
use tabled::{Format, Modify, Style, Table, Tabled};
use tabled::object::Columns;

mod proxy;

fn proxy(via: String) -> Proxy {
    let proxy_uri = format!("http://{}", via).parse().unwrap();
    let proxy = Proxy::new(Intercept::All, proxy_uri);
    // proxy.set_authorization(Authorization::basic("", ""));
    proxy
}

async fn forward(target: String, client_ip: IpAddr, req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let connector = {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_secs(2)));
        connector
    };

    let client = hyper::Client::builder().pool_idle_timeout(Duration::from_secs(2)).build(connector);

    match proxy::call(client_ip, target, req, client).await {
        Ok(response) => { Ok(response) }
        Err(e) => {
            tracing::error!("{:?}", e);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(json!({"msg": format!("{:?}", e)}).to_string()))
                .unwrap())
        }
    }
}

async fn proxy_forward(target: String, client_ip: IpAddr, req: Request<Body>, proxy: Proxy) -> Result<Response<Body>, Infallible> {
    let connector = {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_secs(2)));
        ProxyConnector::from_proxy(connector, proxy).unwrap()
    };

    let client = hyper::Client::builder().pool_idle_timeout(Duration::from_secs(2)).build(connector);

    match proxy::proxy_call(client_ip, target, req, client).await {
        Ok(response) => { Ok(response) }
        Err(e) => {
            tracing::error!("{:?}", e);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(json!({"msg": format!("{:?}", e)}).to_string()))
                .unwrap())
        }
    }
}

#[derive(Debug, PartialEq, Clone, Tabled)]
pub struct Hop {
    pub path: String,
    pub dest: String,
    #[tabled(display_with = "display_option")]
    pub via: Option<String>,
}

fn display_option(o: &Option<String>) -> String {
    match o {
        Some(s) => format!("{}", s),
        None => format!("-"),
    }
}

async fn handle(hops: Vec<Hop>, client_ip: IpAddr, mut req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path();

    tracing::debug!("{}", path);

    for hop in hops {
        if path.starts_with(&hop.path) {
            *req.uri_mut() = remove_prefix(&req, hop.path);

            return match hop.via {
                None => {
                    forward(format!("http://{}", hop.dest), client_ip, req).await
                }
                Some(via) => {
                    proxy_forward(format!("http://{}", hop.dest), client_ip, req, proxy(via.to_string())).await
                }
            };
        }
    }
    panic!()
}

fn remove_prefix(req: &Request<Body>, prefix: String) -> Uri {
    let path = req.uri().path_and_query().unwrap().to_string();
    println!("{}", path);
    match path.is_empty() {
        true => { "/".to_string() }
        false => { path }
    }.replacen(&prefix, "", 1).as_str().parse().unwrap()
}

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long, short)]
    listen: Option<String>,

    #[clap(long, short)]
    proxy: Vec<String>,
}

impl FromStr for Hop {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<String> = s.split("~").map(|c| c.to_string()).collect();
        if parts.len() > 3 || parts.len() < 2 {
            return Err(format!("{} is invalid!", s));
        }
        let path = parts.get(0).unwrap().to_string();
        let dest = parts.get(1).unwrap().to_string();
        let via = parts.get(2).map(|c| c.to_string());
        Ok(Hop { path, dest, via })
    }
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    tracing_subscriber::fmt::init();

    let args: Args = Args::parse();

    let hops: Vec<Result<Hop, String>> = args.proxy.into_iter().map(|arg| arg.parse::<Hop>()).collect();

    if let Some(hop) = hops.iter().find(|hop| hop.is_err()) {
        tracing::error!("{:?}", hop);
        return Err(());
    }

    let hops: Vec<Hop> = hops.into_iter().map(|hop| hop.unwrap()).collect();

    let bind_addr = args.listen.unwrap_or(String::from("127.0.0.1:7007"));
    let addr: SocketAddr = bind_addr.parse().expect("could not parse ip:port");

    let make_svc = make_service_fn(|conn: &AddrStream| {
        let client_ip = conn.remote_addr().ip();
        let hops = hops.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req|
                handle(
                    hops.clone(),
                    client_ip,
                    req,
                )
            ))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    tracing::info!("Running server on {:?}", addr);

    let table = Table::new(&hops)
        .with(Style::rounded())
        .with(Modify::new(Columns::single(0)).with(Format::new(|s| (if s.is_empty() { "/" } else { s }).green().bold().to_string())))
        .with(Modify::new(Columns::single(1)).with(Format::new(|s| s.green().bold().to_string())))
        .with(Modify::new(Columns::new(2..)).with(Format::new(|s| s.green().bold().to_string())))
        .to_string();

    println!("{}", table);

    if let Err(e) = server.await {
        tracing::error!("server error: {}", e);
    }

    Ok(())
}