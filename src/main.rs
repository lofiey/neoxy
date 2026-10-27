//! neoxy —— 按 SNI / 协议特征分流的 TLS 代理（兼容 tls-shunt-proxy 配置格式），并新增 HTTP/3 (QUIC) 支持。
//!
//! 流程：TCP 读 ClientHello → 按 SNI 找 vhost →
//!   · tlsoffloading=false：整条连接原样转发给 default
//!   · tlsoffloading=true ：解开 TLS，嗅探首包 → http / h2 / trojan / 其他，再各走各的 handler
//! UDP 侧：QUIC 终结 → HTTP/3 请求与 h2 共用同一套路由规则。

use std::{
    collections::HashMap,
    convert::Infallible,
    io::{self, BufReader, SeekFrom},
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::{Buf, Bytes};
use futures_util::StreamExt;
use http::{header::*, HeaderValue, Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::{
    body::{Body as HttpBody, Frame, Incoming},
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use rustls::{
    crypto::CryptoProvider,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    ServerConfig,
};
use rustls_acme::{caches::DirCache, AcmeConfig};
use serde::Deserialize;
use tokio::{
    io::{
        copy_bidirectional, copy_bidirectional_with_sizes, AsyncRead, AsyncReadExt, AsyncSeekExt,
        AsyncWrite, AsyncWriteExt, ReadBuf,
    },
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

#[cfg(unix)]
use tokio::net::UnixStream;

type E = Box<dyn std::error::Error + Send + Sync>;
type Body = UnsyncBoxBody<Bytes, E>;

// ════════════════════════════ 配置（与原版 config.yaml 对应） ════════════════════════════

#[derive(Deserialize)]
struct Config {
    #[serde(default)]
    listen: String,
    #[serde(default)]
    redirecthttps: String,
    #[serde(default = "d_in")]
    inboundbuffersize: usize,
    #[serde(default = "d_out")]
    outboundbuffersize: usize,
    #[serde(default)]
    fallback: String,
    // ── 新增 ──
    #[serde(default)]
    http3: bool,
    #[serde(default)]
    acmeemail: String,
    #[serde(default)]
    acmecache: String,
    #[serde(default)]
    acmestaging: bool,
    #[serde(default)]
    vhosts: Vec<VHostCfg>,
}
fn d_in() -> usize {
    4
}
fn d_out() -> usize {
    32
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct VHostCfg {
    name: String,
    tlsoffloading: bool,
    managedcert: bool,
    #[allow(dead_code)]
    keytype: String,
    cert: String,
    key: String,
    alpn: String,
    protocols: String,
    http: HttpCfg,
    http2: Vec<PathRule>,
    trojan: Option<Handler>,
    default: Option<Handler>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct HttpCfg {
    paths: Vec<PathRule>,
    handler: String,
    args: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PathRule {
    path: String,
    trimprefix: String,
    handler: String,
    args: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Handler {
    #[allow(dead_code)]
    handler: String,
    args: String,
}

// ════════════════════════════ 运行时结构 ════════════════════════════

struct VHost {
    cfg: VHostCfg,
    tls: Option<Arc<ServerConfig>>,
    challenge: Option<Arc<ServerConfig>>, // ACME TLS-ALPN-01
}

impl VHost {
    fn has_http(&self) -> bool {
        let h = &self.cfg.http;
        !h.paths.is_empty() || !h.handler.is_empty() || !self.cfg.http2.is_empty()
    }
}

struct Shared {
    fallback: String,
    inbuf: usize,
    outbuf: usize,
    h3: bool,
    port: u16,
    vhosts: HashMap<String, Arc<VHost>>,
}

#[derive(Clone, Copy)]
struct ConnInfo {
    peer: SocketAddr,
    local: SocketAddr,
    h3: bool,
}

// ════════════════════════════ 通用 IO 工具 ════════════════════════════

trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}
type BoxIo = Box<dyn Io>;

/// 先吐出已读取的字节，再继续读底层流（用于回放 ClientHello / 嗅探到的首包）
struct Rewind<S> {
    pre: Bytes,
    inner: S,
}
impl<S> Rewind<S> {
    fn new(pre: Vec<u8>, inner: S) -> Self {
        Self { pre: Bytes::from(pre), inner }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if !self.pre.is_empty() {
            let n = self.pre.len().min(buf.remaining());
            let chunk = self.pre.split_to(n);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 由 mpsc 通道驱动的 HTTP body（用于 h3 请求体 / 文件流式输出）
struct ChanBody(mpsc::Receiver<Result<Bytes, E>>);
impl HttpBody for ChanBody {
    type Data = Bytes;
    type Error = E;
    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, E>>> {
        self.0.poll_recv(cx).map(|o| o.map(|r| r.map(Frame::data)))
    }
}

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|e| -> E { match e {} }).boxed_unsync()
}
fn status(c: StatusCode) -> Response<Body> {
    let mut r = Response::new(full(c.canonical_reason().unwrap_or("")));
    *r.status_mut() = c;
    r
}

// ════════════════════════════ proxyPass 参数 ════════════════════════════

enum Target {
    Tcp(String),
    Unix(String),
    H2c(String),
}
struct ProxyArgs {
    target: Target,
    proxy_protocol: bool,
}
impl ProxyArgs {
    /// 例：`127.0.0.1:40001;proxyProtocol` / `unix:/path/x.sock` / `h2c://localhost:40002`
    fn parse(s: &str) -> Self {
        let mut it = s.split(';');
        let addr = it.next().unwrap_or("").trim();
        let proxy_protocol = it.any(|f| f.trim() == "proxyProtocol");
        let target = if let Some(p) = addr.strip_prefix("unix:") {
            Target::Unix(p.to_string())
        } else if let Some(h) = addr.strip_prefix("h2c://") {
            Target::H2c(h.trim_end_matches('/').to_string())
        } else {
            Target::Tcp(addr.to_string())
        };
        Self { target, proxy_protocol }
    }
}

async fn connect(t: &Target) -> io::Result<BoxIo> {
    match t {
        Target::Tcp(a) | Target::H2c(a) => {
            let s = TcpStream::connect(a.as_str()).await?;
            s.set_nodelay(true).ok();
            Ok(Box::new(s))
        }
        #[cfg(unix)]
        Target::Unix(p) => Ok(Box::new(UnixStream::connect(p).await?)),
        #[cfg(not(unix))]
        Target::Unix(_) => Err(io::Error::new(io::ErrorKind::Unsupported, "unix socket unsupported")),
    }
}

/// PROXY protocol v1
fn proxy_header(ci: &ConnInfo) -> String {
    match (ci.peer.ip().to_canonical(), ci.local.ip().to_canonical()) {
        (IpAddr::V4(p), IpAddr::V4(l)) => {
            format!("PROXY TCP4 {} {} {} {}\r\n", p, l, ci.peer.port(), ci.local.port())
        }
        (IpAddr::V6(p), IpAddr::V6(l)) => {
            format!("PROXY TCP6 {} {} {} {}\r\n", p, l, ci.peer.port(), ci.local.port())
        }
        _ => "PROXY UNKNOWN\r\n".to_string(),
    }
}

/// 原始 TCP 转发（default / trojan / fallback）
async fn raw_proxy<C: AsyncRead + AsyncWrite + Unpin>(
    mut c: C,
    args: &str,
    pre: &[u8],
    ci: &ConnInfo,
    sh: &Shared,
) -> io::Result<()> {
    let a = ProxyArgs::parse(args);
    let mut u = connect(&a.target).await.map_err(|e| {
        eprintln!("[{}] proxyPass {args} 连接失败: {e}", ci.peer);
        e
    })?;
    if a.proxy_protocol {
        u.write_all(proxy_header(ci).as_bytes()).await?;
    }
    if !pre.is_empty() {
        u.write_all(pre).await?;
    }
    copy_bidirectional_with_sizes(&mut c, &mut u, sh.inbuf * 1024, sh.outbuf * 1024).await?;
    Ok(())
}

// ════════════════════════════ ClientHello 解析 ════════════════════════════

#[derive(Default)]
struct Hello {
    sni: Option<String>,
    acme: bool, // ALPN 含 acme-tls/1
}

/// None = 数据还不够；Some = 解析完成（非 TLS 时字段为默认值）
fn parse_hello(b: &[u8]) -> Option<Hello> {
    if b.len() < 5 {
        return None;
    }
    if b[0] != 0x16 {
        return Some(Hello::default());
    }
    let end = 5 + u16::from_be_bytes([b[3], b[4]]) as usize;
    if b.len() < end {
        return None;
    }
    Some(hello_fields(&b[5..end]).unwrap_or_default())
}

fn take<'a>(h: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if h.len() < n {
        return None;
    }
    let (a, b) = h.split_at(n);
    *h = b;
    Some(a)
}
fn take_len<'a>(h: &mut &'a [u8], w: usize) -> Option<&'a [u8]> {
    let l = take(h, w)?.iter().fold(0usize, |a, &x| (a << 8) | x as usize);
    take(h, l)
}

fn hello_fields(mut h: &[u8]) -> Option<Hello> {
    if take(&mut h, 1)?[0] != 0x01 {
        return None;
    }
    take(&mut h, 3 + 2 + 32)?; // 长度 + 版本 + random
    take_len(&mut h, 1)?; // session id
    take_len(&mut h, 2)?; // cipher suites
    take_len(&mut h, 1)?; // compression
    let mut ext = take_len(&mut h, 2)?;
    let mut out = Hello::default();
    while ext.len() >= 4 {
        let ty = u16::from_be_bytes([ext[0], ext[1]]);
        take(&mut ext, 2)?;
        let mut body = take_len(&mut ext, 2)?;
        match ty {
            0 => {
                take(&mut body, 2)?; // server_name_list 长度
                take(&mut body, 1)?; // name_type
                let name = take_len(&mut body, 2)?;
                out.sni = String::from_utf8(name.to_vec()).ok();
            }
            16 => {
                take(&mut body, 2)?; // alpn 列表长度
                while !body.is_empty() {
                    if take_len(&mut body, 1)? == b"acme-tls/1" {
                        out.acme = true;
                    }
                }
            }
            _ => {}
        }
    }
    Some(out)
}

// ════════════════════════════ 解开 TLS 后的流量嗅探 ════════════════════════════

enum Kind {
    Http,
    H2,
    Trojan,
    Other,
}

/// None = 需要更多数据
fn classify(b: &[u8]) -> Option<Kind> {
    const H2: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if b.is_empty() {
        return None;
    }
    if b.starts_with(H2) {
        return Some(Kind::H2);
    }
    if H2.starts_with(b) {
        return None;
    }
    for m in ["GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "] {
        if b.starts_with(m.as_bytes()) {
            return Some(Kind::Http);
        }
        if m.as_bytes().starts_with(b) {
            return None;
        }
    }
    // trojan：56 个十六进制字符 + \r\n
    let hex = |c: &u8| c.is_ascii_hexdigit();
    if b.len() >= 56 && b[..56].iter().all(hex) {
        return match b.get(56..58) {
            Some(x) => Some(if x == b"\r\n" { Kind::Trojan } else { Kind::Other }),
            None if b.len() == 57 && b[56] != b'\r' => Some(Kind::Other),
            None => None,
        };
    }
    if b.len() < 56 && b.iter().all(hex) {
        return None;
    }
    Some(Kind::Other)
}

// ════════════════════════════ TCP 入口 ════════════════════════════

async fn handle_tcp(mut s: TcpStream, sh: Arc<Shared>) -> Result<(), E> {
    s.set_nodelay(true).ok();
    let ci = ConnInfo { peer: s.peer_addr()?, local: s.local_addr()?, h3: false };

    // 1. 读 ClientHello
    let mut buf = Vec::with_capacity(2048);
    let hello = loop {
        let mut tmp = [0u8; 2048];
        let n = timeout(Duration::from_secs(10), s.read(&mut tmp))
            .await
            .map_err(|_| "client hello timeout")??;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(h) = parse_hello(&buf) {
            break h;
        }
        if buf.len() > 20 * 1024 {
            return Ok(());
        }
    };

    // 2. SNI → vhost，未命中走 fallback
    let vh = hello.sni.as_deref().and_then(|n| sh.vhosts.get(&n.to_ascii_lowercase())).cloned();
    let Some(vh) = vh else {
        if !sh.fallback.is_empty() {
            raw_proxy(s, &sh.fallback, &buf, &ci, &sh).await?;
        }
        return Ok(());
    };

    // 3. 不解开 TLS：整条连接交给 default
    if !vh.cfg.tlsoffloading {
        if let Some(d) = &vh.cfg.default {
            raw_proxy(s, &d.args, &buf, &ci, &sh).await?;
        }
        return Ok(());
    }

    // 4. ACME TLS-ALPN-01 验证连接
    if hello.acme {
        if let Some(c) = &vh.challenge {
            let _ = TlsAcceptor::from(c.clone()).accept(Rewind::new(buf, s)).await;
        }
        return Ok(());
    }

    // 5. 解开 TLS
    let Some(tls) = &vh.tls else { return Ok(()) };
    let stream = timeout(Duration::from_secs(10), TlsAcceptor::from(tls.clone()).accept(Rewind::new(buf, s)))
        .await
        .map_err(|_| "tls handshake timeout")??;
    let mut io: BoxIo = Box::new(stream);

    // 6. 嗅探首包
    let mut first = Vec::new();
    let kind = loop {
        let mut tmp = [0u8; 1024];
        match timeout(Duration::from_secs(3), io.read(&mut tmp)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => {
                first.extend_from_slice(&tmp[..n]);
                if let Some(k) = classify(&first) {
                    break k;
                }
                if first.len() > 4096 {
                    break Kind::Other;
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break Kind::Other, // 服务端先发言的协议：超时后按 default 处理
        }
    };
    let io = Rewind::new(first, io);

    // 7. 分流
    match kind {
        Kind::Http | Kind::H2 if vh.has_http() => serve_http(io, vh, sh, ci).await,
        Kind::Trojan if vh.cfg.trojan.is_some() => {
            let t = vh.cfg.trojan.as_ref().unwrap();
            raw_proxy(io, &t.args, &[], &ci, &sh).await.map_err(Into::into)
        }
        _ => {
            if let Some(d) = &vh.cfg.default {
                raw_proxy(io, &d.args, &[], &ci, &sh).await?;
            }
            Ok(())
        }
    }
}

// ════════════════════════════ HTTP（h1 / h2 / h3 共用路由） ════════════════════════════

async fn serve_http(io: Rewind<BoxIo>, vh: Arc<VHost>, sh: Arc<Shared>, ci: ConnInfo) -> Result<(), E> {
    let svc = service_fn(move |req: Request<Incoming>| {
        let (vh, sh) = (vh.clone(), sh.clone());
        async move {
            let req = req.map(|b| b.map_err(|e| -> E { e.into() }).boxed_unsync());
            Ok::<_, Infallible>(handle(req, vh, sh, ci).await)
        }
    });
    auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(io), svc)
        .await?;
    Ok(())
}

async fn handle(req: Request<Body>, vh: Arc<VHost>, sh: Arc<Shared>, ci: ConnInfo) -> Response<Body> {
    let mut resp = match route(req, &vh, &sh, &ci).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[{}] {}: {e}", ci.peer, vh.cfg.name);
            status(StatusCode::BAD_GATEWAY)
        }
    };
    // 告知浏览器可以改用 HTTP/3
    if sh.h3 && !ci.h3 {
        if let Ok(v) = HeaderValue::from_str(&format!("h3=\":{}\"; ma=86400", sh.port)) {
            resp.headers_mut().entry("alt-svc").or_insert(v);
        }
    }
    resp
}

/// 返回 (handler, args, trimprefix)
fn select<'a>(vh: &'a VHost, req: &Request<Body>, ci: &ConnInfo) -> Option<(&'a str, &'a str, &'a str)> {
    let path = req.uri().path();
    let modern = ci.h3 || req.version() == Version::HTTP_2;
    let c = &vh.cfg;
    let pick = |r: &'a PathRule| (r.handler.as_str(), r.args.as_str(), r.trimprefix.as_str());
    if modern && !c.http2.is_empty() {
        return c.http2.iter().find(|r| r.path == "*" || path.starts_with(&r.path)).map(pick);
    }
    let hit = c.http.paths.iter().find(|r| {
        if modern {
            r.path == "*"
        } else {
            r.path != "*" && path.starts_with(&r.path)
        }
    });
    if let Some(r) = hit {
        return Some(pick(r));
    }
    if c.http.handler.is_empty() {
        None
    } else {
        Some((c.http.handler.as_str(), c.http.args.as_str(), ""))
    }
}

async fn route(req: Request<Body>, vh: &VHost, _sh: &Shared, ci: &ConnInfo) -> Result<Response<Body>, E> {
    let Some((handler, args, trim)) = select(vh, &req, ci) else {
        return Ok(status(StatusCode::NOT_FOUND));
    };
    match handler {
        "proxyPass" => reverse_proxy(req, args, trim, ci).await,
        "fileServer" => file_server(req, args, trim).await,
        other => Err(format!("unknown handler: {other}").into()),
    }
}

const HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn trim_path(pq: &str, trim: &str) -> String {
    let (p, q) = match pq.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (pq, None),
    };
    let p = if trim.is_empty() { p } else { p.strip_prefix(trim).unwrap_or(p) };
    let mut p = p.to_string();
    if !p.starts_with('/') {
        p.insert(0, '/');
    }
    match q {
        Some(q) => format!("{p}?{q}"),
        None => p,
    }
}

// ───────────── proxyPass（HTTP 反向代理，支持 WebSocket / h2c） ─────────────

async fn reverse_proxy(mut req: Request<Body>, args: &str, trim: &str, ci: &ConnInfo) -> Result<Response<Body>, E> {
    let a = ProxyArgs::parse(args);
    let h2c = matches!(a.target, Target::H2c(_));
    let upgrading = !h2c && req.headers().contains_key(UPGRADE);
    let on_client = if upgrading { Some(hyper::upgrade::on(&mut req)) } else { None };

    let pq = trim_path(req.uri().path_and_query().map_or("/", |p| p.as_str()), trim);
    let host = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .or_else(|| req.headers().get(HOST).and_then(|v| v.to_str().ok()).map(String::from));
    let uri: Uri = match &a.target {
        Target::H2c(addr) => format!("http://{addr}{pq}"),
        _ => pq,
    }
    .parse()?;

    let (parts, body) = req.into_parts();
    let mut out = Request::new(body);
    *out.method_mut() = parts.method;
    *out.uri_mut() = uri;
    for (k, v) in parts.headers.iter() {
        let n = k.as_str();
        let keep = (upgrading && (n == "upgrade" || n == "connection")) || (h2c && n == "te");
        if (HOP.contains(&n) && !keep) || (h2c && n == "host") {
            continue;
        }
        out.headers_mut().append(k.clone(), v.clone());
    }
    if !h2c && !out.headers().contains_key(HOST) {
        if let Some(h) = host.as_deref().and_then(|h| HeaderValue::from_str(h).ok()) {
            out.headers_mut().insert(HOST, h);
        }
    }
    out.headers_mut().insert("x-forwarded-for", HeaderValue::from_str(&ci.peer.ip().to_canonical().to_string())?);
    out.headers_mut().insert("x-forwarded-proto", HeaderValue::from_static("https"));

    let mut s = connect(&a.target).await?;
    if a.proxy_protocol {
        s.write_all(proxy_header(ci).as_bytes()).await?;
    }
    let io = TokioIo::new(s);

    let mut resp = if h2c {
        let (mut tx, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        tx.send_request(out).await?
    } else {
        let (mut tx, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        tx.send_request(out).await?
    };

    // WebSocket 等协议升级：两端打通后双向拷贝
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(oc) = on_client {
            let ob = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let (Ok(c), Ok(b)) = (oc.await, ob.await) {
                    let _ = copy_bidirectional(&mut TokioIo::new(c), &mut TokioIo::new(b)).await;
                }
            });
            let (p, _) = resp.into_parts();
            return Ok(Response::from_parts(p, full(Bytes::new())));
        }
    }

    for h in HOP {
        resp.headers_mut().remove(h);
    }
    Ok(resp.map(|b| b.map_err(|e| -> E { e.into() }).boxed_unsync()))
}

// ───────────── fileServer（静态网站） ─────────────

fn pdecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut o = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                o.push(v);
                i += 3;
                continue;
            }
        }
        o.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&o).into_owned()
}

fn safe_join(root: &str, p: &str) -> Option<PathBuf> {
    let mut out = PathBuf::from(root);
    for seg in p.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." || seg.contains('\0') || seg.contains('\\') {
            return None;
        }
        out.push(seg);
    }
    Some(out)
}

enum Rg {
    Ignore,
    Bad,
    Ok(u64, u64), // [start, end)
}
fn parse_range(r: &str, len: u64) -> Rg {
    let Some(spec) = r.strip_prefix("bytes=") else { return Rg::Ignore };
    if spec.contains(',') {
        return Rg::Ignore;
    }
    let Some((a, b)) = spec.split_once('-') else { return Rg::Ignore };
    let (s, e) = if a.is_empty() {
        let Ok(n) = b.parse::<u64>() else { return Rg::Ignore };
        if n == 0 {
            return Rg::Bad;
        }
        (len.saturating_sub(n), len)
    } else {
        let Ok(s) = a.parse::<u64>() else { return Rg::Ignore };
        let e = if b.is_empty() {
            len
        } else {
            match b.parse::<u64>() {
                Ok(x) => x.saturating_add(1).min(len),
                Err(_) => return Rg::Ignore,
            }
        };
        (s, e)
    };
    if s >= len || s >= e {
        Rg::Bad
    } else {
        Rg::Ok(s, e)
    }
}

fn file_body(mut f: tokio::fs::File, mut remaining: u64) -> Body {
    let (tx, rx) = mpsc::channel::<Result<Bytes, E>>(4);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let want = buf.len().min(remaining as usize);
            match f.read(&mut buf[..want]).await {
                Ok(0) => break,
                Ok(n) => {
                    remaining -= n as u64;
                    if tx.send(Ok(Bytes::copy_from_slice(&buf[..n]))).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e.into())).await;
                    break;
                }
            }
        }
    });
    ChanBody(rx).boxed_unsync()
}

async fn file_server(req: Request<Body>, root: &str, trim: &str) -> Result<Response<Body>, E> {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        return Ok(status(StatusCode::METHOD_NOT_ALLOWED));
    }
    let p = trim_path(req.uri().path(), trim);
    let Some(mut fp) = safe_join(root, &pdecode(&p)) else {
        return Ok(status(StatusCode::BAD_REQUEST));
    };
    let Ok(mut meta) = tokio::fs::metadata(&fp).await else {
        return Ok(status(StatusCode::NOT_FOUND));
    };
    if meta.is_dir() {
        if !p.ends_with('/') {
            let q = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
            let mut r = status(StatusCode::MOVED_PERMANENTLY);
            r.headers_mut().insert(LOCATION, HeaderValue::from_str(&format!("{}/{}", req.uri().path(), q))?);
            return Ok(r);
        }
        fp.push("index.html");
        match tokio::fs::metadata(&fp).await {
            Ok(m) if m.is_file() => meta = m,
            _ => return Ok(status(StatusCode::NOT_FOUND)),
        }
    }
    if !meta.is_file() {
        return Ok(status(StatusCode::NOT_FOUND));
    }

    let len = meta.len();
    let modified = meta.modified().ok();
    let secs = |t: SystemTime| t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

    if let (Some(m), Some(ims)) = (
        modified,
        req.headers()
            .get(IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| httpdate::parse_http_date(s).ok()),
    ) {
        if secs(m) <= secs(ims) {
            return Ok(status(StatusCode::NOT_MODIFIED));
        }
    }

    let (start, end, partial) = match req.headers().get(RANGE).and_then(|v| v.to_str().ok()) {
        None => (0, len, false),
        Some(r) => match parse_range(r, len) {
            Rg::Ignore => (0, len, false),
            Rg::Ok(s, e) => (s, e, true),
            Rg::Bad => {
                let mut r = status(StatusCode::RANGE_NOT_SATISFIABLE);
                r.headers_mut().insert(CONTENT_RANGE, HeaderValue::from_str(&format!("bytes */{len}"))?);
                return Ok(r);
            }
        },
    };

    let ct = mime_guess::from_path(&fp).first_or_octet_stream().to_string();
    let ct = if ct.starts_with("text/") { format!("{ct}; charset=utf-8") } else { ct };

    let mut rb = Response::builder()
        .status(if partial { StatusCode::PARTIAL_CONTENT } else { StatusCode::OK })
        .header(CONTENT_TYPE, ct)
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_LENGTH, end - start);
    if let Some(m) = modified {
        rb = rb.header(LAST_MODIFIED, httpdate::fmt_http_date(m));
    }
    if partial {
        rb = rb.header(CONTENT_RANGE, format!("bytes {}-{}/{}", start, end - 1, len));
    }
    let body = if *req.method() == Method::HEAD || end == start {
        full(Bytes::new())
    } else {
        let mut f = tokio::fs::File::open(&fp).await?;
        if start > 0 {
            f.seek(SeekFrom::Start(start)).await?;
        }
        file_body(f, end - start)
    };
    Ok(rb.body(body)?)
}

// ════════════════════════════ redirecthttps ════════════════════════════

fn host_only(h: &str) -> &str {
    if h.starts_with('[') {
        h.find(']').map_or(h, |i| &h[..=i])
    } else {
        h.rsplit_once(':').map_or(h, |(a, _)| a)
    }
}

async fn redirect_server(addr: SocketAddr, https_port: u16) -> Result<(), E> {
    let l = TcpListener::bind(addr).await?;
    loop {
        let (s, _) = l.accept().await?;
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| async move {
                let host = req.headers().get(HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
                let port = if https_port == 443 { String::new() } else { format!(":{https_port}") };
                let loc = format!(
                    "https://{}{}{}",
                    host_only(host),
                    port,
                    req.uri().path_and_query().map_or("/", |p| p.as_str())
                );
                let mut r = Response::new(Full::new(Bytes::new()));
                *r.status_mut() = StatusCode::MOVED_PERMANENTLY;
                if let Ok(v) = HeaderValue::from_str(&loc) {
                    r.headers_mut().insert(LOCATION, v);
                }
                Ok::<_, Infallible>(r)
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc).await;
        });
    }
}

// ════════════════════════════ HTTP/3 (QUIC) ════════════════════════════

fn quic_endpoint(
    addr: SocketAddr,
    provider: &Arc<CryptoProvider>,
    map: HashMap<String, Arc<dyn ResolvesServerCert>>,
) -> Result<quinn::Endpoint, E> {
    let mut tls = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SniResolver(map)));
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let qc = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    Ok(quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(qc)), addr)?)
}

async fn serve_quic(ep: quinn::Endpoint, sh: Arc<Shared>) {
    while let Some(inc) = ep.accept().await {
        let sh = sh.clone();
        tokio::spawn(async move {
            let _ = h3_conn(inc, sh).await;
        });
    }
}

async fn h3_conn(inc: quinn::Incoming, sh: Arc<Shared>) -> Result<(), E> {
    let conn = inc.await?;
    let ci = ConnInfo {
        peer: conn.remote_address(),
        local: SocketAddr::new(conn.local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), sh.port),
        h3: true,
    };
    let sni = conn
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.server_name);
    let vh = sni
        .and_then(|n| sh.vhosts.get(&n.to_ascii_lowercase()).cloned())
        .ok_or("unknown sni")?;

    let mut h3c: h3::server::Connection<h3_quinn::Connection, Bytes> =
        h3::server::Connection::new(h3_quinn::Connection::new(conn))
            .await
            .map_err(|e| e.to_string())?;
    while let Ok(Some(resolver)) = h3c.accept().await {
        let (vh, sh) = (vh.clone(), sh.clone());
        tokio::spawn(async move {
            let _ = h3_request(resolver, vh, sh, ci).await;
        });
    }
    Ok(())
}

async fn h3_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    vh: Arc<VHost>,
    sh: Arc<Shared>,
    ci: ConnInfo,
) -> Result<(), E> {
    let (req, stream) = resolver.resolve_request().await.map_err(|e| e.to_string())?;
    let (mut send, mut recv) = stream.split();

    // 请求体：独立任务读 QUIC 流 → 通道 → Body（流式，支持大上传）
    let (tx, rx) = mpsc::channel::<Result<Bytes, E>>(8);
    tokio::spawn(async move {
        loop {
            match recv.recv_data().await {
                Ok(Some(mut b)) => {
                    let d = b.copy_to_bytes(b.remaining());
                    if tx.send(Ok(d)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = tx.send(Err(e.to_string().into())).await;
                    break;
                }
            }
        }
    });
    let (parts, ()) = req.into_parts();
    let req = Request::from_parts(parts, ChanBody(rx).boxed_unsync());

    let resp = handle(req, vh, sh, ci).await;
    let (mut parts, mut body) = resp.into_parts();
    for h in HOP {
        parts.headers.remove(h);
    }
    parts.version = Version::HTTP_3;
    send.send_response(Response::from_parts(parts, ())).await.map_err(|e| e.to_string())?;
    while let Some(f) = body.frame().await {
        match f?.into_data() {
            Ok(d) => send.send_data(d).await.map_err(|e| e.to_string())?,
            Err(f) => {
                if let Ok(t) = f.into_trailers() {
                    send.send_trailers(t).await.map_err(|e| e.to_string())?;
                }
            }
        }
    }
    send.finish().await.map_err(|e| e.to_string())?;
    Ok(())
}

// ════════════════════════════ 证书 / TLS 配置 ════════════════════════════

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);
impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// QUIC 侧：按 SNI 选择各 vhost 的证书（静态或 ACME）
#[derive(Debug)]
struct SniResolver(HashMap<String, Arc<dyn ResolvesServerCert>>);
impl ResolvesServerCert for SniResolver {
    fn resolve(&self, ch: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let r = self.0.get(&ch.server_name()?.to_ascii_lowercase())?.clone();
        r.resolve(ch)
    }
}

fn load_static(cert: &str, key: &str, provider: &CryptoProvider) -> Result<Arc<dyn ResolvesServerCert>, E> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(cert)?))
        .collect::<Result<Vec<_>, _>>()?;
    let k = rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(key)?))?
        .ok_or("no private key found")?;
    let sk = provider.key_provider.load_private_key(k)?;
    Ok(Arc::new(Fixed(Arc::new(CertifiedKey::new(certs, sk)))))
}

fn start_acme(name: &str, cfg: &Config) -> (Arc<dyn ResolvesServerCert>, Arc<ServerConfig>) {
    let cache = if !cfg.acmecache.is_empty() {
        cfg.acmecache.clone()
    } else if let Ok(d) = std::env::var("STATE_DIRECTORY") {
        format!("{}/acme", d.split(':').next().unwrap_or(&d))
    } else {
        // 默认放在可执行文件旁边，如 /opt/neoxy/acme
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("acme").to_string_lossy().into_owned()))
            .unwrap_or_else(|| "./acme-cache".to_string())
    };
    let dir = format!("{cache}/{name}");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("acme[{name}] 无法创建缓存目录 {dir}: {e}（请检查权限，或在配置里设置 acmecache）");
    }
    let mut ac = AcmeConfig::new([name.to_string()])
        .cache(DirCache::new(dir))
        .directory_lets_encrypt(!cfg.acmestaging);
    if !cfg.acmeemail.is_empty() {
        ac = ac.contact_push(format!("mailto:{}", cfg.acmeemail));
    }
    let mut state = ac.state();
    let resolver: Arc<dyn ResolvesServerCert> = state.resolver();
    let challenge = state.challenge_rustls_config();
    let n = name.to_string();
    tokio::spawn(async move {
        while let Some(ev) = state.next().await {
            match ev {
                Ok(ok) => eprintln!("acme[{n}]: {ok:?}"),
                Err(e) => eprintln!("acme[{n}] error: {e:?}"),
            }
        }
    });
    (resolver, challenge)
}

fn parse_versions(p: &str) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, E> {
    let v = |s: &str| match s {
        "tls12" => Ok(12),
        "tls13" => Ok(13),
        _ => Err(format!("bad protocols value: {s}")),
    };
    let parts: Vec<&str> = p.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    let (min, max) = match parts.as_slice() {
        [] => (12, 13),
        [a] => (v(a)?, v(a)?),
        [a, b] => (v(a)?, v(b)?),
        _ => return Err("protocols: expected `min,max`".into()),
    };
    Ok([(12, &rustls::version::TLS12), (13, &rustls::version::TLS13)]
        .into_iter()
        .filter(|(n, _)| *n >= min && *n <= max)
        .map(|(_, x)| x)
        .collect())
}

fn build_tls(
    provider: &Arc<CryptoProvider>,
    v: &VHostCfg,
    resolver: Arc<dyn ResolvesServerCert>,
) -> Result<Arc<ServerConfig>, E> {
    let mut c = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&parse_versions(&v.protocols)?)?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    c.alpn_protocols = v
        .alpn
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.as_bytes().to_vec())
        .collect();
    Ok(Arc::new(c))
}

// ════════════════════════════ main ════════════════════════════

fn config_path() -> String {
    let a: Vec<String> = std::env::args().skip(1).collect();
    for (i, s) in a.iter().enumerate() {
        let s = s.trim_start_matches('-');
        if let Some(v) = s.strip_prefix("config=") {
            return v.to_string();
        }
        if (s == "config" || s == "c") && i + 1 < a.len() {
            return a[i + 1].clone();
        }
    }
    "./config.yaml".into()
}

fn parse_addr(s: &str) -> Result<SocketAddr, E> {
    let s = if s.starts_with(':') { format!("0.0.0.0{s}") } else { s.to_string() };
    s.to_socket_addrs()?.next().ok_or_else(|| format!("bad address: {s}").into())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), E> {
    let path = config_path();
    let text = std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
    let mut cfg: Config = serde_yaml::from_str(&text)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listen = parse_addr(if cfg.listen.is_empty() { "0.0.0.0:443" } else { &cfg.listen })?;

    // 构建各 vhost 的 TLS 配置
    let mut vhosts = HashMap::new();
    let mut sni_map: HashMap<String, Arc<dyn ResolvesServerCert>> = HashMap::new();
    for v in std::mem::take(&mut cfg.vhosts) {
        let name = v.name.trim().to_ascii_lowercase();
        let (mut tls, mut challenge) = (None, None);
        if v.tlsoffloading {
            let r: Arc<dyn ResolvesServerCert> = if v.managedcert {
                let (r, c) = start_acme(&name, &cfg);
                challenge = Some(c);
                r
            } else {
                load_static(&v.cert, &v.key, &provider).map_err(|e| format!("vhost {name}: {e}"))?
            };
            tls = Some(build_tls(&provider, &v, r.clone())?);
            sni_map.insert(name.clone(), r);
        }
        vhosts.insert(name, Arc::new(VHost { cfg: v, tls, challenge }));
    }

    let h3 = cfg.http3 && !sni_map.is_empty();
    let quic = if h3 { Some(quic_endpoint(listen, &provider, sni_map)?) } else { None };

    let sh = Arc::new(Shared {
        fallback: cfg.fallback.clone(),
        inbuf: cfg.inboundbuffersize.max(1),
        outbuf: cfg.outboundbuffersize.max(1),
        h3,
        port: listen.port(),
        vhosts,
    });

    if let Some(ep) = quic {
        tokio::spawn(serve_quic(ep, sh.clone()));
        eprintln!("http3 (quic) listening on udp {listen}");
    }
    if !cfg.redirecthttps.is_empty() {
        let a = parse_addr(&cfg.redirecthttps)?;
        let port = listen.port();
        tokio::spawn(async move {
            if let Err(e) = redirect_server(a, port).await {
                eprintln!("redirecthttps: {e}");
            }
        });
    }

    let l = TcpListener::bind(listen).await?;
    eprintln!("listening on tcp {listen}");
    loop {
        let (s, _) = l.accept().await?;
        let sh = sh.clone();
        tokio::spawn(async move {
            let _ = handle_tcp(s, sh).await;
        });
    }
}
