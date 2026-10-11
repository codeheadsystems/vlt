//! The S3 backend: blocking requests over `ureq` with rustls (the `ring` provider) and the
//! platform's trust roots, signed with AWS Signature Version 4 by `rusty-s3`.
//!
//! Requests carry their signature in the query string, and every header that matters
//! (`If-None-Match`, `If-Match`, `x-amz-expected-bucket-owner`) is among the signed headers. Keys
//! passed in are prefix-relative; the backend adds the vault's prefix. AWS endpoints use
//! virtual-hosted addressing; any other endpoint (RustFS) is addressed path-style, because RustFS
//! serves virtual-hosted requests only when configured to.

use crate::backend::{Backend, Delete, Etag, Get, Put};
use crate::error::{OfflineKind, StoreError};
use crate::probe::{
    BackendKind, BucketProbe, Lifecycle, ObjectLock, RawCond, RawResponse, Versioning,
};
use crate::retry::{Backoff, is_transient};
use crate::xml;
use core::fmt;
use rusty_s3::{Bucket, Method, UrlStyle};
use std::io::{self, Read};
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use vlt_core::enroll::VaultConfig;
use zeroize::Zeroizing;

/// How long a signature stays valid. Each request is signed just before it is sent.
const SIGNATURE_LIFETIME_SECS: u64 = 300;
/// The largest XML body vlt reads: a listing page of 1,000 keys with version IDs.
const XML_MAX: usize = 8 * 1024 * 1024;
/// The most of an error body read to find its code.
const ERROR_BODY_MAX: usize = 64 * 1024;

/// A device's S3 access key. The secret is zeroed on drop and appears in no error or log; like the
/// other secret types, `Credentials` implements neither `Debug` nor `Display`.
///
/// ```compile_fail
/// let c = vlt_store::Credentials::new("AKID".into(), zeroize::Zeroizing::new("secret".into()));
/// let _ = format!("{:?}", c);
/// ```
pub struct Credentials {
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
}

impl Credentials {
    /// Credentials from an access key ID and its secret.
    pub fn new(access_key_id: String, secret_access_key: Zeroizing<String>) -> Credentials {
        Credentials {
            access_key_id,
            secret_access_key,
        }
    }

    /// The access key ID, which is not secret: RustFS and CloudTrail see it on every request.
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }
}

/// Where a vault's bucket is and how to talk to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Config {
    /// Endpoint (empty for AWS), region, bucket, and prefix, from the vault configuration line.
    pub location: VaultConfig,
    /// Admits a plain `http://` endpoint to a non-loopback host (`--allow-http`). A loopback host
    /// is always admitted.
    pub allow_http: bool,
    /// The bucket owner's AWS account ID, sent as `x-amz-expected-bucket-owner` on every request
    /// when set.
    pub expected_bucket_owner: Option<String>,
    /// Limit on name resolution and on opening the connection.
    pub connect_timeout: Duration,
    /// Limit on each of sending the request, receiving the response head, and receiving the body.
    pub io_timeout: Duration,
    /// Retries of conditional writes answered with a transient `5xx`.
    pub backoff: Backoff,
}

impl S3Config {
    /// A configuration with no expected owner, `http` only to loopback, a 3 s connect timeout, a
    /// 60 s I/O timeout, and the default [`Backoff`].
    pub fn new(location: VaultConfig) -> S3Config {
        S3Config {
            location,
            allow_http: false,
            expected_bucket_owner: None,
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(60),
            backoff: Backoff::default(),
        }
    }

    /// Which rows of the probe's backend table apply: AWS when the endpoint is empty.
    pub fn kind(&self) -> BackendKind {
        if self.location.endpoint.is_empty() {
            BackendKind::Aws
        } else {
            BackendKind::Other
        }
    }
}

/// A request as handed to the transport, already signed.
pub(crate) struct HttpRequest<'a> {
    pub(crate) method: Method,
    pub(crate) url: Url,
    pub(crate) headers: Vec<(&'static str, String)>,
    pub(crate) body: Option<&'a [u8]>,
}

/// A response from the transport, with its body unread.
pub(crate) struct HttpResponse {
    pub(crate) status: u16,
    /// Header names in lowercase.
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Box<dyn Read + Send>,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Sends one HTTP request. Only transport failures are errors; every response is returned.
pub(crate) trait Transport: Send + Sync {
    fn send(&self, req: &HttpRequest<'_>) -> Result<HttpResponse, StoreError>;
}

/// Classifies an I/O error from a socket or a body read.
fn classify_io(e: &io::Error) -> StoreError {
    if let Some(inner) = e.get_ref() {
        if let Some(tls) = inner.downcast_ref::<rustls::Error>() {
            return StoreError::Tls {
                detail: tls.to_string(),
            };
        }
        if let Some(u) = inner.downcast_ref::<ureq::Error>() {
            return classify_ureq_ref(u);
        }
    }
    StoreError::Offline(match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => OfflineKind::Timeout,
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::NetworkDown
        | io::ErrorKind::AddrNotAvailable => OfflineKind::Connect,
        _ => OfflineKind::ConnectionLost,
    })
}

/// Classifies a `ureq` error: transport failures are offline, TLS failures are not.
fn classify_ureq_ref(e: &ureq::Error) -> StoreError {
    match e {
        ureq::Error::Timeout(_) => StoreError::Offline(OfflineKind::Timeout),
        ureq::Error::HostNotFound => StoreError::Offline(OfflineKind::Dns),
        ureq::Error::ConnectionFailed | ureq::Error::ConnectProxyFailed(_) => {
            StoreError::Offline(OfflineKind::Connect)
        }
        ureq::Error::Io(io) => classify_io(io),
        ureq::Error::Rustls(tls) => StoreError::Tls {
            detail: tls.to_string(),
        },
        ureq::Error::Tls(detail) => StoreError::Tls {
            detail: (*detail).to_owned(),
        },
        ureq::Error::BodyStalled => StoreError::Offline(OfflineKind::Timeout),
        _ => StoreError::Protocol {
            what: "HTTP transport error",
        },
    }
}

/// The agent settings. `env_proxy` is the proxy the environment names (`HTTPS_PROXY`,
/// `HTTP_PROXY`, `ALL_PROXY`); only an HTTPS endpoint uses it, so a plain `http://` request to a
/// loopback or `--allow-http` endpoint never leaves through a proxy.
fn agent_config(
    config: &S3Config,
    https: bool,
    tls: ureq::tls::TlsConfig,
    env_proxy: Option<ureq::Proxy>,
) -> ureq::config::Config {
    let (connect, io) = (Some(config.connect_timeout), Some(config.io_timeout));
    ureq::Agent::config_builder()
        .tls_config(tls)
        .https_only(https)
        .proxy(if https { env_proxy } else { None })
        .http_status_as_error(false)
        .max_redirects(0)
        .user_agent("vlt")
        .timeout_resolve(connect)
        .timeout_connect(connect)
        .timeout_send_request(io)
        .timeout_send_body(io)
        .timeout_recv_response(io)
        .timeout_recv_body(io)
        .build()
}

/// The real transport.
struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    fn new(config: &S3Config, https: bool) -> Result<UreqTransport, StoreError> {
        use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};
        let roots = if https {
            let loaded = rustls_native_certs::load_native_certs();
            if loaded.certs.is_empty() {
                return Err(StoreError::Tls {
                    detail: "no trusted root certificates found on this system".into(),
                });
            }
            let certs: Vec<Certificate<'static>> = loaded
                .certs
                .iter()
                .map(|c| Certificate::from_der(c.as_ref()).to_owned())
                .collect();
            RootCerts::new_with_certs(&certs)
        } else {
            RootCerts::new_with_certs(&[])
        };
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .root_certs(roots)
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .build();
        let agent = agent_config(config, https, tls, ureq::Proxy::try_from_env()).into();
        Ok(UreqTransport { agent })
    }
}

impl Transport for UreqTransport {
    fn send(&self, req: &HttpRequest<'_>) -> Result<HttpResponse, StoreError> {
        let mut builder = ureq::http::Request::builder()
            .method(req.method.to_str())
            .uri(req.url.as_str());
        for (name, value) in &req.headers {
            builder = builder.header(*name, value.as_str());
        }
        let bad = |_| StoreError::Protocol {
            what: "request could not be built",
        };
        let result = match req.body {
            Some(body) => self.agent.run(builder.body(body).map_err(bad)?),
            None => self.agent.run(builder.body(()).map_err(bad)?),
        };
        let resp = result.map_err(|e| classify_ureq_ref(&e))?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
            .collect();
        Ok(HttpResponse {
            status,
            headers,
            body: Box::new(resp.into_body().into_reader()),
        })
    }
}

/// Reads a body, refusing it before reading when `Content-Length` exceeds `max`, and stopping one
/// byte past `max` otherwise.
fn read_body(resp: &mut HttpResponse, max: usize, key: &str) -> Result<Vec<u8>, StoreError> {
    let too_large = || StoreError::TooLarge {
        key: key.to_owned(),
    };
    if let Some(len) = resp.header("content-length") {
        let len: u64 = len.trim().parse().map_err(|_| StoreError::Protocol {
            what: "bad Content-Length",
        })?;
        if len > max as u64 {
            return Err(too_large());
        }
    }
    let mut buf = Vec::new();
    Read::by_ref(&mut resp.body)
        .take(max as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| classify_io(&e))?;
    if buf.len() > max {
        return Err(too_large());
    }
    Ok(buf)
}

fn etag_header(resp: &HttpResponse) -> Result<Etag, StoreError> {
    resp.header("etag")
        .filter(|e| !e.is_empty())
        .map(|e| Etag(e.to_owned()))
        .ok_or(StoreError::Protocol {
            what: "missing ETag",
        })
}

/// The S3 error code of an error response.
fn error_code(mut resp: HttpResponse, method: Method) -> Option<String> {
    if method == Method::Head {
        return None;
    }
    let mut buf = Vec::new();
    Read::by_ref(&mut resp.body)
        .take(ERROR_BODY_MAX as u64)
        .read_to_end(&mut buf)
        .ok()?;
    xml::error_code(&buf)
}

fn http_error(resp: HttpResponse, method: Method, key: &str) -> StoreError {
    let status = resp.status;
    StoreError::Http {
        status,
        code: error_code(resp, method),
        method: method.to_str(),
        key: key.to_owned(),
    }
}

fn raw_response(resp: HttpResponse, method: Method) -> RawResponse {
    let status = resp.status;
    let etag = resp.header("etag").map(|e| Etag(e.to_owned()));
    let code = if resp.is_success() {
        None
    } else {
        error_code(resp, method)
    };
    RawResponse { status, etag, code }
}

/// The S3 backend for one vault.
pub struct S3Backend {
    bucket: Bucket,
    prefix: String,
    credentials: Credentials,
    expected_owner: Option<String>,
    backoff: Backoff,
    transport: Box<dyn Transport>,
}

impl fmt::Debug for S3Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Backend")
            .field("bucket", &self.bucket.name())
            .field("prefix", &self.prefix)
            .field("access_key_id", &self.credentials.access_key_id())
            .finish_non_exhaustive()
    }
}

/// Checks the configuration and works out the bucket's base URL. Returns whether it is HTTPS.
fn bucket_for(config: &S3Config) -> Result<(Bucket, bool), StoreError> {
    let loc = &config.location;
    // The vault configuration line's rules are the single source of truth for these values.
    let line = loc.to_line().map_err(|_| StoreError::InvalidConfig {
        what: "endpoint, region, bucket, or prefix",
    })?;
    VaultConfig::from_line(&line, config.allow_http).map_err(|_| StoreError::InvalidConfig {
        what: "plain http endpoint (needs --allow-http)",
    })?;
    if let Some(owner) = &config.expected_bucket_owner
        && !(owner.len() == 12 && owner.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(StoreError::InvalidConfig {
            what: "expected bucket owner",
        });
    }
    let (endpoint, style) = if loc.endpoint.is_empty() {
        let host = format!("https://s3.{}.amazonaws.com", loc.region);
        // A dotted bucket name breaks the wildcard certificate under virtual-hosted addressing.
        let style = if loc.bucket.contains('.') {
            UrlStyle::Path
        } else {
            UrlStyle::VirtualHost
        };
        (host, style)
    } else {
        (loc.endpoint.clone(), UrlStyle::Path)
    };
    let url: Url = endpoint
        .parse()
        .map_err(|_| StoreError::InvalidConfig { what: "endpoint" })?;
    let https = url.scheme() == "https";
    let bucket = Bucket::new(url, style, loc.bucket.clone(), loc.region.clone())
        .map_err(|_| StoreError::InvalidConfig { what: "endpoint" })?;
    Ok((bucket, https))
}

impl S3Backend {
    /// A backend for `config`, signing with `credentials`. Loads the platform's trust roots for an
    /// HTTPS endpoint.
    pub fn new(config: &S3Config, credentials: Credentials) -> Result<S3Backend, StoreError> {
        let (_, https) = bucket_for(config)?;
        let transport = UreqTransport::new(config, https)?;
        S3Backend::with_transport(config, credentials, Box::new(transport))
    }

    pub(crate) fn with_transport(
        config: &S3Config,
        credentials: Credentials,
        transport: Box<dyn Transport>,
    ) -> Result<S3Backend, StoreError> {
        let (bucket, _) = bucket_for(config)?;
        Ok(S3Backend {
            bucket,
            prefix: config.location.prefix.clone(),
            credentials,
            expected_owner: config.expected_bucket_owner.clone(),
            backoff: config.backoff,
            transport,
        })
    }

    /// Signs and sends one request. `key` is prefix-relative; `None` addresses the bucket.
    fn send(
        &self,
        method: Method,
        key: Option<&str>,
        query: &[(&str, &str)],
        mut headers: Vec<(&'static str, String)>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, StoreError> {
        let url = match key {
            Some(k) => self.bucket.object_url(&format!("{}{k}", self.prefix)),
            None => Ok(self.bucket.base_url().clone()),
        }
        .map_err(|_| StoreError::InvalidConfig { what: "key" })?;
        if let Some(owner) = &self.expected_owner {
            headers.push(("x-amz-expected-bucket-owner", owner.clone()));
        }
        // The signer merges these with `host` and needs both sorted by name.
        headers.sort_by(|a, b| a.0.cmp(b.0));
        let mut query = query.to_vec();
        query.sort_unstable();
        let url = rusty_s3::signing::sign(
            &jiff::Timestamp::now(),
            method,
            url,
            &self.credentials.access_key_id,
            &self.credentials.secret_access_key,
            None,
            self.bucket.region(),
            SIGNATURE_LIFETIME_SECS,
            query.iter().copied(),
            headers.iter().map(|(k, v)| (*k, v.as_str())),
        );
        self.transport.send(&HttpRequest {
            method,
            url,
            headers,
            body,
        })
    }

    /// A bucket-level `GET` returning its XML body; `absent` names the error code (with `404`) that
    /// means "not configured", which returns `None`, as does `501 NotImplemented`.
    fn bucket_xml(
        &self,
        query: &[(&str, &str)],
        absent: Option<&str>,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let mut resp = self.send(Method::Get, None, query, vec![], None)?;
        if resp.status == 200 {
            return read_body(&mut resp, XML_MAX, "").map(Some);
        }
        let status = resp.status;
        let code = error_code(resp, Method::Get);
        let not_configured = match (status, absent) {
            (501, Some(_)) => true,
            (404, Some(want)) => code.as_deref() == Some(want),
            _ => false,
        };
        if not_configured {
            return Ok(None);
        }
        Err(StoreError::Http {
            status,
            code,
            method: "GET",
            key: String::new(),
        })
    }

    fn must_xml(&self, query: &[(&str, &str)]) -> Result<Vec<u8>, StoreError> {
        Ok(self.bucket_xml(query, None)?.unwrap_or_default())
    }

    /// One `ListObjectVersions` page at the bucket root, or `None` when the backend answers
    /// `501 NotImplemented`.
    fn versions_page(
        &self,
        max_keys: Option<&str>,
        marker: Option<&(String, String)>,
    ) -> Result<Option<xml::VersionsPage>, StoreError> {
        let mut query = vec![("versions", "")];
        if let Some(m) = max_keys {
            query.push(("max-keys", m));
        }
        if let Some((k, v)) = marker {
            query.push(("key-marker", k.as_str()));
            if !v.is_empty() {
                query.push(("version-id-marker", v.as_str()));
            }
        }
        let mut resp = self.send(Method::Get, None, &query, vec![], None)?;
        match resp.status {
            200 => Ok(Some(xml::versions_page(&read_body(
                &mut resp, XML_MAX, "",
            )?)?)),
            501 => Ok(None),
            _ => Err(http_error(resp, Method::Get, "")),
        }
    }

    /// One `ListObjectsV2` page under a bucket-absolute prefix.
    fn objects_page(
        &self,
        prefix: Option<&str>,
        max_keys: Option<&str>,
        token: Option<&str>,
    ) -> Result<xml::ObjectsPage, StoreError> {
        let mut query = vec![("list-type", "2")];
        if let Some(p) = prefix {
            query.push(("prefix", p));
        }
        if let Some(m) = max_keys {
            query.push(("max-keys", m));
        }
        if let Some(t) = token {
            query.push(("continuation-token", t));
        }
        xml::objects_page(&self.must_xml(&query)?)
    }

    /// Retries a conditional write while the server answers with a transient `5xx`, which is
    /// neither a failed condition nor offline.
    fn retrying(&self, op: impl FnMut() -> Result<Put, StoreError>) -> Result<Put, StoreError> {
        self.backoff.run(
            op,
            |r| matches!(r, Err(e) if e.status().is_some_and(is_transient)),
        )
    }

    fn create_once(&self, key: &str, bytes: &[u8]) -> Result<Put, StoreError> {
        let headers = Self::cond_headers(&RawCond::IfNoneMatchStar);
        let resp = self.send(Method::Put, Some(key), &[], headers, Some(bytes))?;
        match resp.status {
            200 => Ok(Put::Written {
                etag: etag_header(&resp)?,
            }),
            412 => Ok(Put::PreconditionFailed),
            _ => Err(http_error(resp, Method::Put, key)),
        }
    }

    fn replace_once(&self, key: &str, bytes: &[u8], expected: &Etag) -> Result<Put, StoreError> {
        let headers = Self::cond_headers(&RawCond::IfMatch(expected.clone()));
        let resp = self.send(Method::Put, Some(key), &[], headers, Some(bytes))?;
        match resp.status {
            200 => Ok(Put::Written {
                etag: etag_header(&resp)?,
            }),
            412 => Ok(Put::PreconditionFailed),
            404 | 409 => {
                // `404 NoSuchKey`: `If-Match` on a missing key. `409 ConditionalRequestConflict`:
                // AWS's answer to a concurrent conditional write, which its documentation says
                // to retry. Both mean "re-read and try again".
                let status = resp.status;
                let code = error_code(resp, Method::Put);
                let retry = matches!(
                    (status, code.as_deref()),
                    (404, None | Some("NoSuchKey")) | (409, Some("ConditionalRequestConflict"))
                );
                if retry {
                    return Ok(Put::PreconditionFailed);
                }
                Err(StoreError::Http {
                    status,
                    code,
                    method: "PUT",
                    key: key.to_owned(),
                })
            }
            _ => Err(http_error(resp, Method::Put, key)),
        }
    }

    fn cond_headers(cond: &RawCond) -> Vec<(&'static str, String)> {
        match cond {
            RawCond::IfNoneMatchStar => vec![("if-none-match", "*".to_owned())],
            RawCond::IfMatch(e) => vec![("if-match", e.0.clone())],
            RawCond::None => vec![],
            RawCond::IfNoneMatch(v) => vec![("if-none-match", v.clone())],
        }
    }
}

impl Backend for S3Backend {
    fn get(
        &self,
        key: &str,
        if_none_match: Option<&Etag>,
        max_len: usize,
    ) -> Result<Get, StoreError> {
        let headers = if_none_match
            .map(|e| vec![("if-none-match", e.0.clone())])
            .unwrap_or_default();
        let mut resp = self.send(Method::Get, Some(key), &[], headers, None)?;
        match resp.status {
            200 => {
                let etag = etag_header(&resp)?;
                let bytes = read_body(&mut resp, max_len, key)?;
                Ok(Get::Found { bytes, etag })
            }
            304 => Ok(Get::NotModified),
            404 => {
                let code = error_code(resp, Method::Get);
                match code.as_deref() {
                    None | Some("NoSuchKey") => Ok(Get::NotFound),
                    _ => Err(StoreError::Http {
                        status: 404,
                        code,
                        method: "GET",
                        key: key.to_owned(),
                    }),
                }
            }
            _ => Err(http_error(resp, Method::Get, key)),
        }
    }

    fn exists(&self, key: &str) -> Result<bool, StoreError> {
        let resp = self.send(Method::Head, Some(key), &[], vec![], None)?;
        match resp.status {
            200 => Ok(true),
            404 => Ok(false),
            _ => Err(http_error(resp, Method::Head, key)),
        }
    }

    fn create(&self, key: &str, bytes: &[u8]) -> Result<Put, StoreError> {
        self.retrying(|| self.create_once(key, bytes))
    }

    fn replace(&self, key: &str, bytes: &[u8], expected: &Etag) -> Result<Put, StoreError> {
        self.retrying(|| self.replace_once(key, bytes, expected))
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let full = format!("{}{prefix}", self.prefix);
        let mut keys = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let page = self.objects_page(Some(&full), None, token.as_deref())?;
            keys.extend(
                page.objects
                    .into_iter()
                    .filter_map(|(k, _)| k.strip_prefix(&self.prefix).map(str::to_owned)),
            );
            match page.next {
                None => break,
                Some(next) if token.as_ref() == Some(&next) => {
                    return Err(StoreError::Protocol {
                        what: "listing repeats its continuation token",
                    });
                }
                Some(next) => token = Some(next),
            }
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    fn delete(&self, key: &str) -> Result<Delete, StoreError> {
        let resp = self.send(Method::Delete, Some(key), &[], vec![], None)?;
        match resp.status {
            200 | 204 => Ok(Delete::Deleted),
            404 => Ok(Delete::NotFound),
            _ => Err(http_error(resp, Method::Delete, key)),
        }
    }
}

impl BucketProbe for S3Backend {
    fn versioning(&self) -> Result<Versioning, StoreError> {
        xml::versioning(&self.must_xml(&[("versioning", "")])?)
    }

    fn object_lock(&self) -> Result<ObjectLock, StoreError> {
        match self.bucket_xml(
            &[("object-lock", "")],
            Some("ObjectLockConfigurationNotFoundError"),
        )? {
            Some(body) => xml::object_lock(&body),
            None => Ok(ObjectLock {
                enabled: false,
                default_mode: None,
            }),
        }
    }

    fn lifecycle(&self) -> Result<Lifecycle, StoreError> {
        match self.bucket_xml(&[("lifecycle", "")], Some("NoSuchLifecycleConfiguration"))? {
            Some(body) => xml::lifecycle(
                &body,
                &format!("{}header", self.prefix),
                &format!("{}index", self.prefix),
            ),
            None => Ok(Lifecycle::default()),
        }
    }

    fn any_object_or_version(&self) -> Result<Option<String>, StoreError> {
        if let Some(page) = self.versions_page(Some("1"), None)? {
            return Ok(page.entries.into_iter().next().map(|(k, _)| k));
        }
        let page = self.objects_page(None, Some("1"), None)?;
        Ok(page.objects.into_iter().next().map(|(k, _)| k))
    }

    fn put_raw(&self, key: &str, bytes: &[u8], cond: &RawCond) -> Result<RawResponse, StoreError> {
        let resp = self.send(
            Method::Put,
            Some(key),
            &[],
            Self::cond_headers(cond),
            Some(bytes),
        )?;
        Ok(raw_response(resp, Method::Put))
    }

    fn create_multipart(&self, key: &str) -> Result<RawResponse, StoreError> {
        let mut resp = self.send(
            Method::Post,
            Some(key),
            &[("uploads", "")],
            vec![],
            Some(b""),
        )?;
        if !resp.is_success() {
            return Ok(raw_response(resp, Method::Post));
        }
        // The check failed and an upload is open. Abort it if the key is allowed to; the result
        // does not change the check.
        let upload_id = read_body(&mut resp, ERROR_BODY_MAX, key)
            .ok()
            .and_then(|b| xml::parse(&b).ok())
            .and_then(|root| root.text_of("UploadId").map(str::to_owned));
        if let Some(id) = upload_id {
            let _ = self.send(
                Method::Delete,
                Some(key),
                &[("uploadId", id.as_str())],
                vec![],
                None,
            );
        }
        Ok(RawResponse {
            status: resp.status,
            etag: None,
            code: None,
        })
    }

    fn delete_raw(&self, key: &str) -> Result<RawResponse, StoreError> {
        let resp = self.send(Method::Delete, Some(key), &[], vec![], None)?;
        Ok(raw_response(resp, Method::Delete))
    }

    fn backoff(&self) -> Backoff {
        self.backoff
    }

    fn total_stored_bytes(&self) -> Result<u64, StoreError> {
        let mut total = 0u64;
        let mut marker: Option<(String, String)> = None;
        while let Some(page) = self.versions_page(None, marker.as_ref())? {
            total += page.entries.iter().map(|(_, s)| s).sum::<u64>();
            match page.next {
                None => return Ok(total),
                Some(next) if marker.as_ref() == Some(&next) => {
                    return Err(StoreError::Protocol {
                        what: "listing repeats its marker",
                    });
                }
                Some(next) => marker = Some(next),
            }
        }
        if marker.is_some() {
            return Err(StoreError::Protocol {
                what: "version listing stopped part-way",
            });
        }
        // No ListObjectVersions: an unversioned backend, where current objects are all there is.
        let mut token: Option<String> = None;
        loop {
            let page = self.objects_page(None, None, token.as_deref())?;
            total += page.objects.iter().map(|(_, s)| s).sum::<u64>();
            match page.next {
                None => return Ok(total),
                Some(next) if token.as_ref() == Some(&next) => {
                    return Err(StoreError::Protocol {
                        what: "listing repeats its continuation token",
                    });
                }
                Some(next) => token = Some(next),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct Recorded {
        method: Method,
        url: Url,
        headers: Vec<(&'static str, String)>,
        body: Option<Vec<u8>>,
    }

    impl Recorded {
        fn query(&self, name: &str) -> Option<String> {
            self.url
                .query_pairs()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
        }

        fn signed_headers(&self) -> Vec<String> {
            self.query("X-Amz-SignedHeaders")
                .unwrap()
                .split(';')
                .map(str::to_owned)
                .collect()
        }

        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.as_str())
        }
    }

    /// A body that fails the test if anything reads it.
    struct Unreadable;

    impl Read for Unreadable {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("the body was read");
        }
    }

    enum Body {
        Bytes(Vec<u8>),
        Unreadable,
    }

    type CannedResponse = (u16, Vec<(String, String)>, Body);

    struct Canned {
        requests: Mutex<Vec<Recorded>>,
        responses: Mutex<VecDeque<CannedResponse>>,
    }

    #[derive(Clone)]
    struct Shared(Arc<Canned>);

    impl Transport for Shared {
        fn send(&self, req: &HttpRequest<'_>) -> Result<HttpResponse, StoreError> {
            self.0.requests.lock().unwrap().push(Recorded {
                method: req.method,
                url: req.url.clone(),
                headers: req.headers.clone(),
                body: req.body.map(<[u8]>::to_vec),
            });
            let (status, headers, body) = self
                .0
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("no canned response left");
            let body: Box<dyn Read + Send> = match body {
                Body::Bytes(b) => Box::new(io::Cursor::new(b)),
                Body::Unreadable => Box::new(Unreadable),
            };
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        }
    }

    impl Shared {
        fn reply(&self, status: u16, headers: &[(&str, &str)], body: &[u8]) -> &Self {
            self.reply_with(status, headers, Body::Bytes(body.to_vec()))
        }

        fn reply_with(&self, status: u16, headers: &[(&str, &str)], body: Body) -> &Self {
            let headers = headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            self.0
                .responses
                .lock()
                .unwrap()
                .push_back((status, headers, body));
            self
        }

        fn requests(&self) -> std::sync::MutexGuard<'_, Vec<Recorded>> {
            self.0.requests.lock().unwrap()
        }
    }

    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn creds() -> Credentials {
        Credentials::new("AKIAIOSFODNN7EXAMPLE".into(), Zeroizing::new(SECRET.into()))
    }

    fn location(endpoint: &str, bucket: &str) -> VaultConfig {
        VaultConfig {
            vault_id: [7; 16],
            region: "us-east-1".into(),
            bucket: bucket.into(),
            prefix: "vlt/".into(),
            endpoint: endpoint.into(),
        }
    }

    fn rustfs(owner: Option<&str>) -> (S3Backend, Shared) {
        let mut config = S3Config::new(location("http://127.0.0.1:19000", "vlt-test"));
        config.expected_bucket_owner = owner.map(str::to_owned);
        config.backoff = Backoff {
            attempts: 3,
            base: Duration::ZERO,
        };
        let t = Shared(Arc::new(Canned {
            requests: Mutex::new(vec![]),
            responses: Mutex::new(VecDeque::new()),
        }));
        let b = S3Backend::with_transport(&config, creds(), Box::new(t.clone())).unwrap();
        (b, t)
    }

    fn error_body(code: &str) -> Vec<u8> {
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>m</Message></Error>").into_bytes()
    }

    #[test]
    fn get_adds_prefix_and_signs_conditional_and_owner_headers() {
        let (b, t) = rustfs(Some("111122223333"));
        t.reply(200, &[("etag", "\"e2\""), ("content-length", "3")], b"abc");
        let got = b.get("index", Some(&Etag("\"e1\"".into())), 10).unwrap();
        assert_eq!(
            got,
            Get::Found {
                bytes: b"abc".to_vec(),
                etag: Etag("\"e2\"".into())
            }
        );
        let reqs = t.requests();
        let r = &reqs[0];
        assert_eq!(r.method, Method::Get);
        assert_eq!(r.url.host_str(), Some("127.0.0.1"));
        assert_eq!(r.url.path(), "/vlt-test/vlt/index");
        assert_eq!(
            r.signed_headers(),
            ["host", "if-none-match", "x-amz-expected-bucket-owner"]
        );
        assert_eq!(r.header("if-none-match"), Some("\"e1\""));
        assert_eq!(
            r.header("x-amz-expected-bucket-owner"),
            Some("111122223333")
        );
        assert_eq!(
            r.query("X-Amz-Algorithm").as_deref(),
            Some("AWS4-HMAC-SHA256")
        );
        assert!(
            r.query("X-Amz-Credential")
                .unwrap()
                .starts_with("AKIAIOSFODNN7EXAMPLE/")
        );
        assert!(r.query("X-Amz-Signature").is_some());
        assert!(!r.url.as_str().contains(SECRET));
    }

    #[test]
    fn no_owner_header_without_an_owner() {
        let (b, t) = rustfs(None);
        t.reply(404, &[], &error_body("NoSuchKey"));
        assert_eq!(b.get("header", None, 10).unwrap(), Get::NotFound);
        let reqs = t.requests();
        assert_eq!(reqs[0].signed_headers(), ["host"]);
        assert!(reqs[0].headers.is_empty());
    }

    #[test]
    fn create_sends_if_none_match_star() {
        let (b, t) = rustfs(Some("111122223333"));
        t.reply(200, &[("etag", "\"new\"")], b"").reply(
            412,
            &[],
            &error_body("PreconditionFailed"),
        );
        let key = "e/00112233445566778899aabbccddeeff";
        assert_eq!(
            b.create(key, b"cipher").unwrap(),
            Put::Written {
                etag: Etag("\"new\"".into())
            }
        );
        assert_eq!(b.create(key, b"cipher").unwrap(), Put::PreconditionFailed);
        let reqs = t.requests();
        assert_eq!(reqs[0].method, Method::Put);
        assert_eq!(reqs[0].url.path(), format!("/vlt-test/vlt/{key}"));
        assert_eq!(reqs[0].header("if-none-match"), Some("*"));
        assert_eq!(
            reqs[0].signed_headers(),
            ["host", "if-none-match", "x-amz-expected-bucket-owner"]
        );
        assert_eq!(reqs[0].body.as_deref(), Some(&b"cipher"[..]));
    }

    #[test]
    fn replace_sends_if_match_and_maps_retryable_answers() {
        let (b, t) = rustfs(None);
        let etag = Etag("\"old\"".into());
        t.reply(200, &[("etag", "\"new\"")], b"")
            .reply(412, &[], &error_body("PreconditionFailed"))
            .reply(404, &[], &error_body("NoSuchKey"))
            .reply(409, &[], &error_body("ConditionalRequestConflict"))
            .reply(404, &[], &error_body("NoSuchBucket"))
            .reply(403, &[], &error_body("AccessDenied"));
        assert!(matches!(
            b.replace("index", b"x", &etag).unwrap(),
            Put::Written { .. }
        ));
        for _ in 0..3 {
            assert_eq!(
                b.replace("index", b"x", &etag).unwrap(),
                Put::PreconditionFailed
            );
        }
        assert_eq!(
            b.replace("index", b"x", &etag).unwrap_err(),
            StoreError::Http {
                status: 404,
                code: Some("NoSuchBucket".into()),
                method: "PUT",
                key: "index".into()
            }
        );
        let denied = b.replace("header", b"x", &etag).unwrap_err();
        assert_eq!(denied.status(), Some(403));
        // AccessDenied on a write is not a rejected key.
        assert!(!denied.is_access_key_rejected());
        let reqs = t.requests();
        assert_eq!(reqs[0].header("if-match"), Some("\"old\""));
        assert_eq!(reqs[0].signed_headers(), ["host", "if-match"]);
    }

    #[test]
    fn conditional_writes_retry_transient_server_errors() {
        let (b, t) = rustfs(None);
        let e = Etag("\"old\"".into());
        t.reply(503, &[], &error_body("SlowDownRead"))
            .reply(200, &[("etag", "\"a\"")], b"")
            .reply(500, &[], &error_body("InternalError"))
            .reply(412, &[], &error_body("PreconditionFailed"))
            .reply(503, &[], b"")
            .reply(503, &[], b"")
            .reply(503, &[], &error_body("SlowDownRead"))
            .reply(501, &[], &error_body("NotImplemented"))
            .reply(403, &[], &error_body("AccessDenied"));
        assert!(matches!(
            b.create("index", b"x").unwrap(),
            Put::Written { .. }
        ));
        assert_eq!(
            b.replace("index", b"x", &e).unwrap(),
            Put::PreconditionFailed
        );
        // Three attempts, then the last 503 is the answer.
        assert_eq!(
            b.replace("index", b"x", &e).unwrap_err(),
            StoreError::Http {
                status: 503,
                code: Some("SlowDownRead".into()),
                method: "PUT",
                key: "index".into()
            }
        );
        // 501 and 403 are not retried.
        assert_eq!(b.create("index", b"x").unwrap_err().status(), Some(501));
        assert_eq!(b.create("index", b"x").unwrap_err().status(), Some(403));
        assert_eq!(t.requests().len(), 9);
    }

    #[test]
    fn content_length_over_the_cap_is_refused_unread() {
        let (b, t) = rustfs(None);
        t.reply_with(
            200,
            &[("etag", "\"e\""), ("content-length", "131073")],
            Body::Unreadable,
        );
        assert_eq!(
            b.get("header", None, 131_072).unwrap_err(),
            StoreError::TooLarge {
                key: "header".into()
            }
        );
    }

    #[test]
    fn chunked_body_over_the_cap_is_refused() {
        let (b, t) = rustfs(None);
        t.reply(200, &[("etag", "\"e\"")], &[0u8; 11])
            .reply(200, &[("etag", "\"e\"")], &[0u8; 10]);
        assert_eq!(
            b.get("index", None, 10).unwrap_err(),
            StoreError::TooLarge {
                key: "index".into()
            }
        );
        assert!(matches!(
            b.get("index", None, 10).unwrap(),
            Get::Found { .. }
        ));
    }

    #[test]
    fn get_status_mapping() {
        let (b, t) = rustfs(None);
        t.reply(304, &[("etag", "\"e\"")], b"")
            .reply(404, &[], b"")
            .reply(404, &[], &error_body("NoSuchBucket"))
            .reply(200, &[], b"no etag")
            .reply(403, &[], &error_body("InvalidAccessKeyId"))
            .reply(403, &[], &error_body("AccessDenied"))
            .reply(503, &[], &error_body("SlowDownRead"));
        let e = Etag("\"e\"".into());
        assert_eq!(b.get("index", Some(&e), 10).unwrap(), Get::NotModified);
        assert_eq!(b.get("index", None, 10).unwrap(), Get::NotFound);
        assert_eq!(b.get("index", None, 10).unwrap_err().status(), Some(404));
        assert_eq!(
            b.get("index", None, 10).unwrap_err(),
            StoreError::Protocol {
                what: "missing ETag"
            }
        );
        assert!(
            b.get("index", None, 10)
                .unwrap_err()
                .is_access_key_rejected()
        );
        assert!(
            b.get("header", None, 10)
                .unwrap_err()
                .is_access_key_rejected()
        );
        let slow = b.get("index", None, 10).unwrap_err();
        assert_eq!(
            slow,
            StoreError::Http {
                status: 503,
                code: Some("SlowDownRead".into()),
                method: "GET",
                key: "index".into()
            }
        );
        assert!(!slow.is_offline());
    }

    #[test]
    fn exists_is_head() {
        let (b, t) = rustfs(None);
        t.reply(200, &[], b"")
            .reply(404, &[], b"")
            .reply(403, &[], b"");
        assert!(b.exists("header").unwrap());
        assert!(!b.exists("header").unwrap());
        assert_eq!(b.exists("header").unwrap_err().status(), Some(403));
        assert!(t.requests().iter().all(|r| r.method == Method::Head));
    }

    #[test]
    fn list_follows_continuation_tokens_and_strips_the_prefix() {
        let (b, t) = rustfs(None);
        t.reply(
            200,
            &[],
            b"<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>vlt/e/02</Key></Contents><NextContinuationToken>a+b/c=</NextContinuationToken></ListBucketResult>",
        )
        .reply(
            200,
            &[],
            b"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>vlt/e/01</Key></Contents></ListBucketResult>",
        );
        assert_eq!(b.list("e/").unwrap(), vec!["e/01", "e/02"]);
        let reqs = t.requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].url.path(), "/vlt-test/");
        assert_eq!(reqs[0].query("list-type").as_deref(), Some("2"));
        assert_eq!(reqs[0].query("prefix").as_deref(), Some("vlt/e/"));
        assert_eq!(reqs[0].query("continuation-token"), None);
        assert_eq!(
            reqs[1].query("continuation-token").as_deref(),
            Some("a+b/c=")
        );
    }

    #[test]
    fn list_refuses_a_repeated_token() {
        let (b, t) = rustfs(None);
        let page = b"<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>same</NextContinuationToken></ListBucketResult>";
        t.reply(200, &[], page).reply(200, &[], page);
        assert!(matches!(
            b.list("").unwrap_err(),
            StoreError::Protocol { .. }
        ));
    }

    #[test]
    fn any_object_lists_versions_at_the_root() {
        let (b, t) = rustfs(None);
        t.reply(
            200,
            &[],
            b"<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>k</NextKeyMarker><DeleteMarker><Key>other/x</Key></DeleteMarker></ListVersionsResult>",
        );
        assert_eq!(
            b.any_object_or_version().unwrap().as_deref(),
            Some("other/x")
        );
        let reqs = t.requests();
        assert_eq!(reqs[0].url.path(), "/vlt-test/");
        assert_eq!(reqs[0].query("versions").as_deref(), Some(""));
        assert_eq!(reqs[0].query("max-keys").as_deref(), Some("1"));
        assert_eq!(reqs[0].query("prefix"), None);
    }

    #[test]
    fn any_object_falls_back_to_list_objects_v2() {
        let (b, t) = rustfs(None);
        t.reply(501, &[], &error_body("NotImplemented")).reply(
            200,
            &[],
            b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>",
        );
        assert_eq!(b.any_object_or_version().unwrap(), None);
        let reqs = t.requests();
        assert_eq!(reqs[1].query("list-type").as_deref(), Some("2"));
        assert_eq!(reqs[1].query("max-keys").as_deref(), Some("1"));
        assert_eq!(reqs[1].query("prefix"), None);
    }

    #[test]
    fn total_bytes_pages_through_versions() {
        let (b, t) = rustfs(None);
        t.reply(
            200,
            &[],
            b"<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>vlt/e/01</NextKeyMarker><NextVersionIdMarker>v 1</NextVersionIdMarker><Version><Key>vlt/e/01</Key><Size>10</Size></Version><DeleteMarker><Key>vlt/e/01</Key></DeleteMarker></ListVersionsResult>",
        )
        .reply(
            200,
            &[],
            b"<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>vlt/index</Key><Size>32</Size></Version></ListVersionsResult>",
        );
        assert_eq!(b.total_stored_bytes().unwrap(), 42);
        let reqs = t.requests();
        assert_eq!(reqs[1].query("key-marker").as_deref(), Some("vlt/e/01"));
        assert_eq!(reqs[1].query("version-id-marker").as_deref(), Some("v 1"));
        // The space is percent-encoded as `%20`, which is how it was signed.
        assert!(reqs[1].url.as_str().contains("version-id-marker=v%201"));
    }

    #[test]
    fn total_bytes_without_versions_sums_current_objects() {
        let (b, t) = rustfs(None);
        t.reply(501, &[], b"").reply(
            200,
            &[],
            b"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>vlt/header</Key><Size>5</Size></Contents><Contents><Key>vlt/index</Key><Size>6</Size></Contents></ListBucketResult>",
        );
        assert_eq!(b.total_stored_bytes().unwrap(), 11);
    }

    #[test]
    fn settings_reads() {
        let (b, t) = rustfs(None);
        t.reply(
            200,
            &[],
            b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        )
        .reply(404, &[], &error_body("ObjectLockConfigurationNotFoundError"))
        .reply(404, &[], &error_body("NoSuchLifecycleConfiguration"))
        .reply(404, &[], &error_body("NoSuchBucket"))
        .reply(
            200,
            &[],
            b"<LifecycleConfiguration><Rule><Filter><Prefix>vlt/header</Prefix></Filter><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>365</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>",
        );
        assert_eq!(b.versioning().unwrap(), Versioning::Enabled);
        assert_eq!(
            b.object_lock().unwrap(),
            ObjectLock {
                enabled: false,
                default_mode: None
            }
        );
        assert_eq!(b.lifecycle().unwrap(), Lifecycle::default());
        assert_eq!(b.lifecycle().unwrap_err().status(), Some(404));
        assert_eq!(
            b.lifecycle().unwrap(),
            Lifecycle {
                header_noncurrent_days: Some(365),
                index_noncurrent_days: None
            }
        );
        let reqs = t.requests();
        assert_eq!(reqs[0].query("versioning").as_deref(), Some(""));
        assert_eq!(reqs[1].query("object-lock").as_deref(), Some(""));
        assert_eq!(reqs[2].query("lifecycle").as_deref(), Some(""));
    }

    #[test]
    fn raw_requests_return_every_status() {
        let (b, t) = rustfs(Some("111122223333"));
        t.reply(200, &[("etag", "\"h\"")], b"")
            .reply(412, &[], &error_body("PreconditionFailed"))
            .reply(501, &[], &error_body("NotImplemented"))
            .reply(403, &[], &error_body("AccessDenied"))
            .reply(403, &[], &error_body("AccessDenied"));
        let r = b
            .put_raw("header", b"h", &RawCond::IfNoneMatchStar)
            .unwrap();
        assert_eq!(
            r,
            RawResponse {
                status: 200,
                etag: Some(Etag("\"h\"".into())),
                code: None
            }
        );
        let r = b
            .put_raw("header", b"h", &RawCond::IfMatch(Etag("\"0\"".into())))
            .unwrap();
        assert_eq!(r.status, 412);
        assert_eq!(r.code.as_deref(), Some("PreconditionFailed"));
        let r = b
            .put_raw("e/01", b"", &RawCond::IfNoneMatch("\"x\"".into()))
            .unwrap();
        assert_eq!(r.status, 501);
        assert_eq!(b.put_raw("e/02", b"", &RawCond::None).unwrap().status, 403);
        assert_eq!(b.delete_raw("e/03").unwrap().status, 403);
        let reqs = t.requests();
        assert_eq!(reqs[1].header("if-match"), Some("\"0\""));
        assert_eq!(reqs[2].header("if-none-match"), Some("\"x\""));
        assert_eq!(
            reqs[3].signed_headers(),
            ["host", "x-amz-expected-bucket-owner"]
        );
        assert_eq!(reqs[4].method, Method::Delete);
    }

    #[test]
    fn multipart_create_is_refused_or_aborted() {
        let (b, t) = rustfs(None);
        t.reply(403, &[], &error_body("AccessDenied"))
            .reply(
                200,
                &[],
                b"<InitiateMultipartUploadResult><Bucket>vlt-test</Bucket><Key>vlt/e/01</Key><UploadId>up-1</UploadId></InitiateMultipartUploadResult>",
            )
            .reply(204, &[], b"");
        assert_eq!(b.create_multipart("e/01").unwrap().status, 403);
        assert_eq!(b.create_multipart("e/01").unwrap().status, 200);
        let reqs = t.requests();
        assert_eq!(reqs[0].method, Method::Post);
        assert_eq!(reqs[0].query("uploads").as_deref(), Some(""));
        assert_eq!(reqs[2].method, Method::Delete);
        assert_eq!(reqs[2].query("uploadId").as_deref(), Some("up-1"));
    }

    #[test]
    fn aws_addressing() {
        let mut loc = location("", "my-vault");
        loc.region = "eu-west-1".into();
        let t = Shared(Arc::new(Canned {
            requests: Mutex::new(vec![]),
            responses: Mutex::new(VecDeque::from([(404, vec![], Body::Bytes(vec![]))])),
        }));
        let config = S3Config::new(loc.clone());
        assert_eq!(config.kind(), BackendKind::Aws);
        let b = S3Backend::with_transport(&config, creds(), Box::new(t.clone())).unwrap();
        b.get("header", None, 1).unwrap();
        let reqs = t.requests();
        assert_eq!(
            reqs[0].url.host_str(),
            Some("my-vault.s3.eu-west-1.amazonaws.com")
        );
        assert_eq!(reqs[0].url.scheme(), "https");
        assert_eq!(reqs[0].url.path(), "/vlt/header");
        assert!(
            reqs[0]
                .query("X-Amz-Credential")
                .unwrap()
                .contains("/eu-west-1/s3/aws4_request")
        );

        loc.bucket = "my.vault".into();
        let (bucket, https) = bucket_for(&S3Config::new(loc)).unwrap();
        assert!(https);
        assert_eq!(
            bucket.base_url().as_str(),
            "https://s3.eu-west-1.amazonaws.com/my.vault/"
        );
    }

    #[test]
    fn config_validation() {
        let plain = S3Config::new(location("http://example.com", "vlt-test"));
        assert_eq!(
            bucket_for(&plain).unwrap_err(),
            StoreError::InvalidConfig {
                what: "plain http endpoint (needs --allow-http)"
            }
        );
        let allowed = S3Config {
            allow_http: true,
            ..plain
        };
        assert!(bucket_for(&allowed).is_ok());
        assert!(bucket_for(&S3Config::new(location("http://localhost:9000", "b-1"))).is_ok());
        let mut owner = S3Config::new(location("", "my-vault"));
        owner.expected_bucket_owner = Some("12345".into());
        assert_eq!(
            bucket_for(&owner).unwrap_err(),
            StoreError::InvalidConfig {
                what: "expected bucket owner"
            }
        );
        let mut bad_prefix = location("", "my-vault");
        bad_prefix.prefix = "no-slash".into();
        assert!(bucket_for(&S3Config::new(bad_prefix)).is_err());
    }

    #[test]
    fn plain_http_never_uses_the_environment_proxy() {
        let proxy = || Some(ureq::Proxy::new("http://proxy.example:3128").unwrap());
        let tls = || ureq::tls::TlsConfig::builder().build();
        let local = S3Config::new(location("http://127.0.0.1:9000", "b-1"));
        let (_, https) = bucket_for(&local).unwrap();
        assert!(!https);
        assert!(
            agent_config(&local, https, tls(), proxy())
                .proxy()
                .is_none()
        );
        let remote = S3Config {
            allow_http: true,
            ..S3Config::new(location("http://example.com", "b-1"))
        };
        let (_, https) = bucket_for(&remote).unwrap();
        assert!(
            agent_config(&remote, https, tls(), proxy())
                .proxy()
                .is_none()
        );
        let aws = S3Config::new(location("", "b-1"));
        let (_, https) = bucket_for(&aws).unwrap();
        assert!(https);
        let c = agent_config(&aws, https, tls(), proxy());
        assert_eq!(
            c.proxy().map(|p| p.uri().to_string()),
            Some("http://proxy.example:3128/".to_owned())
        );
        assert!(agent_config(&aws, https, tls(), None).proxy().is_none());
    }

    #[test]
    fn backend_debug_hides_the_secret() {
        let (b, _) = rustfs(None);
        let shown = format!("{b:?}");
        assert!(shown.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!shown.contains(SECRET));
    }

    #[test]
    fn https_backend_loads_platform_roots() {
        S3Backend::new(&S3Config::new(location("", "my-vault")), creds()).unwrap();
    }

    fn real(port: u16, io_timeout: Duration) -> S3Backend {
        let mut config = S3Config::new(location(&format!("http://127.0.0.1:{port}"), "b-1"));
        config.connect_timeout = Duration::from_secs(2);
        config.io_timeout = io_timeout;
        S3Backend::new(&config, creds()).unwrap()
    }

    #[test]
    fn closed_port_is_offline() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let err = real(port, Duration::from_secs(2))
            .get("index", None, 10)
            .unwrap_err();
        assert_eq!(err, StoreError::Offline(OfflineKind::Connect));
        assert!(err.is_offline());
    }

    #[test]
    fn silent_server_is_a_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Accept and hold the connection without answering.
        let holder = std::thread::spawn(move || {
            let conn = listener.accept();
            std::thread::sleep(Duration::from_millis(1500));
            drop(conn);
        });
        let err = real(port, Duration::from_millis(300))
            .get("index", None, 10)
            .unwrap_err();
        assert_eq!(err, StoreError::Offline(OfflineKind::Timeout));
        holder.join().unwrap();
    }

    #[test]
    fn dropped_connection_is_offline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let closer = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = conn.read(&mut buf);
            // Close without a response.
        });
        let err = real(port, Duration::from_secs(2))
            .get("index", None, 10)
            .unwrap_err();
        assert!(err.is_offline(), "{err:?}");
        closer.join().unwrap();
    }

    #[test]
    fn real_transport_round_trip() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = conn.read(&mut buf).unwrap();
                req.extend_from_slice(&buf[..n]);
            }
            conn.write_all(
                b"HTTP/1.1 200 OK\r\nETag: \"abc\"\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
            )
            .unwrap();
            String::from_utf8(req).unwrap()
        });
        let got = real(port, Duration::from_secs(2))
            .get("index", Some(&Etag("\"old\"".into())), 10)
            .unwrap();
        assert_eq!(
            got,
            Get::Found {
                bytes: b"hello".to_vec(),
                etag: Etag("\"abc\"".into())
            }
        );
        let req = server.join().unwrap().to_ascii_lowercase();
        assert!(req.starts_with("get /b-1/vlt/index?"));
        assert!(req.contains("\r\nif-none-match: \"old\"\r\n"));
        assert!(req.contains("x-amz-signedheaders=host%3bif-none-match"));
    }
}
