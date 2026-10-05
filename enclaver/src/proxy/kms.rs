use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, Error, Result};
use async_trait::async_trait;
use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4::SigningParams;
use aws_smithy_runtime::expiring_cache::ExpiringCache;
use aws_smithy_runtime_api::client::identity::Identity;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::http::uri::{Authority, Scheme};
use hyper::{Method, Request, Response, StatusCode, Uri};
use json::{object, JsonValue};
use lazy_static::lazy_static;
use aws_smithy_types::error::display::DisplayErrorContext;
use log::{debug, trace, warn};
use regex::Regex;

use crate::http_util::HttpHandler;
use crate::keypair::KeyPair;
use crate::nsm::{AttestationParams, AttestationProvider};

static X_AMZ_TARGET: HeaderName = HeaderName::from_static("x-amz-target");

static X_AMZ_JSON: HeaderValue = HeaderValue::from_static("application/x-amz-json-1.1");

const X_AMZ_CREDENTIAL: &str = "X-Amz-Credential";

const ATTESTING_ACTIONS: [&str; 5] = [
    "TrentService.Decrypt",
    "TrentService.DeriveSharedSecret",
    "TrentService.GenerateDataKey",
    "TrentService.GenerateDataKeyPair",
    "TrentService.GenerateRandom",
];

const KMS_SERVICE_NAME: &str = "kms";

// Used to parse out the required fields out of the Authorization header or query parameters.
// TODO: make it work using string references to avoid numerous copies.
struct CredentialScope {
    region: String,
    service: String,
}

impl CredentialScope {
    fn from_request(head: &hyper::http::request::Parts) -> Result<Self> {
        lazy_static! {
            // e.g.: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, ...
            static ref HEADER_RE: Regex = Regex::new(r"AWS4\-HMAC\-SHA256 Credential=.*?/.*?/(.*?)/(.*?)/aws4_request,").unwrap();
            static ref QUERY_RE: Regex = Regex::new(r".*?/.*?/(.*?)/(.*?)/aws4_request").unwrap();
        }

        use std::ops::Deref;

        // Look for the signature either in the Authorization HTTP header or in a query string
        let (cred, re) = match head.headers.get(hyper::header::AUTHORIZATION) {
            Some(authz) => (authz.to_str()?.to_string(), HEADER_RE.deref()),
            None => {
                let cred = amz_credential_query(&head.uri)
                    .ok_or(anyhow!("No AWS SigV4 found in the request"))?;
                (cred, QUERY_RE.deref())
            }
        };

        debug!("CredentialScope: {cred}");

        let groups = re.captures(&cred).ok_or(anyhow!(
            "{} header has an invalid format",
            http::header::AUTHORIZATION
        ))?;

        Ok(Self {
            region: groups.get(1).unwrap().as_str().to_string(),
            service: groups.get(2).unwrap().as_str().to_string(),
        })
    }

    fn validate(&self) -> Result<()> {
        if self.service != KMS_SERVICE_NAME {
            return Err(anyhow!(
                "Received request signed for a non-KMS ({}) service",
                self.service
            ));
        }

        Ok(())
    }
}

struct KmsRequestIncoming {
    head: hyper::http::request::Parts,
    body: hyper::body::Bytes,
}

impl KmsRequestIncoming {
    async fn recv(req: Request<Full<Bytes>>) -> Result<Self> {
        let (head, body) = req.into_parts();
        let body = body.collect().await?.to_bytes();

        Ok(Self { head, body })
    }

    fn method(&self) -> &Method {
        &self.head.method
    }

    fn path(&self) -> &str {
        self.head.uri.path()
    }

    fn target(&self) -> Option<&HeaderValue> {
        self.head.headers.get(&X_AMZ_TARGET)
    }

    fn content_type(&self) -> &HeaderValue {
        &X_AMZ_JSON
    }

    fn body_as_json(&self) -> Result<JsonValue> {
        Ok(json::parse(std::str::from_utf8(&self.body)?)?)
    }

    fn is_attesting_action(&self) -> bool {
        if self.head.method == Method::POST && self.head.uri.path() == "/" {
            if let Some(target) = self.target() {
                let action = target.to_str().unwrap();
                return ATTESTING_ACTIONS
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(action));
            }
        }

        false
    }

    fn credential_scope(&self) -> Result<CredentialScope> {
        CredentialScope::from_request(&self.head)
    }
}

struct KmsRequestOutgoing {
    inner: Request<Bytes>,
}

impl KmsRequestOutgoing {
    fn new(authority: Authority, action: &HeaderValue, body: JsonValue) -> Result<Self> {
        let body_bytes = Bytes::copy_from_slice(json::stringify(body).as_bytes());

        let uri = Uri::builder()
            .scheme(Scheme::HTTPS)
            .authority(authority)
            .path_and_query("/")
            .build()?;

        let inner = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(&X_AMZ_TARGET, action)
            .header(hyper::header::CONTENT_TYPE, &X_AMZ_JSON)
            .body(body_bytes)?;

        Ok(Self { inner })
    }

    fn from_incoming(req_in: KmsRequestIncoming, authority: Authority) -> Result<Self> {
        let action = req_in.target().ok_or(anyhow!("KMS Action is missing"))?;

        let uri = Uri::builder()
            .scheme(Scheme::HTTPS)
            .authority(authority)
            .path_and_query(req_in.path())
            .build()?;

        let inner = Request::builder()
            .method(req_in.method())
            .uri(uri)
            .header(&X_AMZ_TARGET, action)
            .header(hyper::header::CONTENT_TYPE, req_in.content_type())
            .body(req_in.body)?;

        Ok(Self { inner })
    }

    fn sign(mut self, credentials: Credentials, region: &str) -> Result<Request<Full<Bytes>>> {
        let expires = SystemTime::now() + Duration::from_secs(3600);
        let identity = Identity::new(credentials, Some(expires));

        let signing_settings = SigningSettings::default();
        let signing_params = SigningParams::builder()
            .identity(&identity)
            .region(region)
            .name(KMS_SERVICE_NAME)
            .time(SystemTime::now())
            .settings(signing_settings)
            .build()?;

        let signable_request = SignableRequest::new(
            self.inner.method().as_str(),
            self.inner.uri().to_string(),
            self.inner
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str(), v.to_str().unwrap())),
            SignableBody::Bytes(self.inner.body()),
        )?;

        // Sign and then apply the signature to the request
        let signed = aws_sigv4::http_request::sign(
            signable_request,
            &aws_sigv4::http_request::SigningParams::V4(signing_params),
        )
        .map_err(Error::msg)?;

        let (signing_instructions, _signature) = signed.into_parts();
        signing_instructions.apply_to_request_http1x(&mut self.inner);

        // Convert Request<Bytes> to Request<Body>
        let (head, bytes_body) = self.inner.into_parts();

        let req = Request::from_parts(head, Full::new(bytes_body));

        trace!(
            "Signed request auth: {}",
            req.headers()
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap()
        );
        Ok(req)
    }
}

pub trait KmsEndpointProvider {
    fn endpoint(&self, region: &str) -> String;
}

/// How long before their expiry cached credentials are replaced. EC2 offers
/// the rotated set at least 5 minutes before the old one expires, so a
/// refresh this late gets the new set while this clock is at most a minute
/// ahead.
const CREDENTIALS_REFRESH_BEFORE: Duration = Duration::from_secs(240);

/// How long a refresh that brought no set beyond `CREDENTIALS_REFRESH_BEFORE`,
/// or none at all, holds off the next one.
const CREDENTIALS_RETRY_AFTER: Duration = Duration::from_secs(20);

/// How long a refresh may take before the cache stops waiting for it.
const CREDENTIALS_REFRESH_TIMEOUT: Duration = Duration::from_secs(5);

/// The cache holds no credentials that have not expired.
#[derive(Debug)]
pub struct CredentialsUnavailable(String);

impl std::fmt::Display for CredentialsUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no unexpired instance-role credentials: {}", self.0)
    }
}

impl std::error::Error for CredentialsUnavailable {}

/// Credentials from `provider`, fetched again only once the cached set is
/// within `CREDENTIALS_REFRESH_BEFORE` of its expiry; concurrent callers
/// share one fetch. A fetch that yields no set beyond that margin (the IMDS
/// provider hands back its last set when IMDS fails) keeps the newest set
/// that is still valid for `CREDENTIALS_RETRY_AFTER`, and fails once none is.
/// A set without an expiry is not cached.
pub struct CredentialsCache {
    provider: SharedCredentialsProvider,
    cache: ExpiringCache<Credentials, Error>,
    refresh_timeout: Duration,
    /// The newest set with an expiry, and when a failed refresh may be retried.
    last: Mutex<(Option<Credentials>, Option<SystemTime>)>,
}

impl CredentialsCache {
    pub fn new(provider: SharedCredentialsProvider) -> Self {
        Self::with_timeout(provider, CREDENTIALS_REFRESH_TIMEOUT)
    }

    fn with_timeout(provider: SharedCredentialsProvider, refresh_timeout: Duration) -> Self {
        Self {
            provider,
            cache: ExpiringCache::new(CREDENTIALS_REFRESH_BEFORE),
            refresh_timeout,
            last: Mutex::new((None, None)),
        }
    }

    pub async fn get(&self) -> Result<Credentials> {
        self.get_at(SystemTime::now()).await
    }

    async fn get_at(&self, now: SystemTime) -> Result<Credentials> {
        if let Some(creds) = self.cache.yield_or_clear_if_expired(now).await {
            return Ok(creds);
        }
        self.cache.get_or_load(|| self.load(now)).await
    }

    /// The set to cache and the time `ExpiringCache` should take as its expiry.
    async fn load(&self, now: SystemTime) -> Result<(Credentials, SystemTime)> {
        if let (_, Some(retry_at)) = *self.last.lock().unwrap() {
            if now < retry_at {
                return Err(CredentialsUnavailable(format!("next refresh at {retry_at:?}")).into());
            }
        }
        let started = Instant::now();
        let fetched = tokio::time::timeout(self.refresh_timeout, self.provider.provide_credentials()).await;
        let now = now + started.elapsed();
        let fetched = match fetched {
            Ok(Ok(creds)) => match creds.expiry() {
                None => return Ok((creds, now)),
                Some(expiry) if expiry > now + CREDENTIALS_REFRESH_BEFORE => {
                    *self.last.lock().unwrap() = (Some(creds.clone()), None);
                    return Ok((creds, expiry));
                }
                Some(_) => Some(creds),
            },
            Ok(Err(err)) => {
                warn!("Refreshing the KMS proxy's credentials failed: {}", DisplayErrorContext(&err));
                None
            }
            Err(_) => {
                warn!("Refreshing the KMS proxy's credentials took over {:?}", self.refresh_timeout);
                None
            }
        };
        let mut last = self.last.lock().unwrap();
        let retry_at = now + CREDENTIALS_RETRY_AFTER;
        last.1 = Some(retry_at);
        let newest = [fetched, last.0.take()].into_iter().flatten().max_by_key(|c| c.expiry());
        last.0 = newest.clone();
        match newest.and_then(|c| c.expiry().filter(|e| *e > now).map(|e| (c, e))) {
            Some((creds, expiry)) => {
                warn!("No credentials valid beyond {CREDENTIALS_REFRESH_BEFORE:?}; serving a set expiring at {expiry:?} until {retry_at:?}");
                Ok((creds, expiry.min(retry_at) + CREDENTIALS_REFRESH_BEFORE))
            }
            None => Err(CredentialsUnavailable(format!("next refresh at {retry_at:?}")).into()),
        }
    }
}

pub struct KmsProxyConfig {
    pub client: Box<dyn HttpClient + Send + Sync>,
    pub credentials: CredentialsCache,
    pub keypair: Arc<KeyPair>,
    pub attester: Box<dyn AttestationProvider + Send + Sync>,
    pub endpoints: Arc<dyn KmsEndpointProvider + Send + Sync>,
}

impl KmsProxyConfig {
    pub fn get_authority(&self, region: &str) -> Authority {
        let endpoint = self.endpoints.endpoint(region);
        Authority::from_maybe_shared(endpoint).unwrap()
    }
    pub async fn credentials(&self) -> Result<Credentials> {
        self.credentials.get().await
    }
}

pub struct KmsProxyHandler {
    config: KmsProxyConfig,
}

impl KmsProxyHandler {
    pub fn new(config: KmsProxyConfig) -> Self {
        Self { config }
    }

    async fn handle_attesting_action(
        &self,
        req_in: KmsRequestIncoming,
    ) -> Result<Response<Full<Bytes>>> {
        // Take the original request, insert "Recipient": <RecipientInfo> into the body json,
        // re-sign the request and send it off.
        debug!("Handling attesting action");

        let credential = req_in.credential_scope()?;
        credential.validate()?;

        let region = credential.region;
        let authority = self.config.get_authority(&region);

        let mut body_obj = req_in.body_as_json()?;

        let attestation_doc = self.get_attestation()?;

        body_obj.insert(
            "Recipient",
            object! {
                "AttestationDocument": json::JsonValue::String(base64::encode(&attestation_doc)),
                "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            },
        )?;

        let req_out = KmsRequestOutgoing::new(authority, req_in.target().unwrap(), body_obj)?;

        // Send the request to the actual KMS
        let resp = self.send(req_out, &region).await?;

        // Decode the response
        self.handle_response(resp).await
    }

    fn get_attestation(&self) -> Result<Vec<u8>> {
        self.config.attester.attestation(AttestationParams {
            nonce: None,
            user_data: None,
            public_key: Some(self.config.keypair.public_key_as_der()?),
        })
    }

    async fn handle_response(&self, resp: Response<Full<Bytes>>) -> Result<Response<Full<Bytes>>> {
        let (mut head, body) = resp.into_parts();
        head.headers.remove(hyper::header::CONTENT_LENGTH);

        let body = body.collect().await?.to_bytes();

        if head.status != StatusCode::OK {
            trace!("Response body: {:?}", std::str::from_utf8(&body));
            return Ok(bytes_response(head, &body));
        }

        let body_val = json::parse(std::str::from_utf8(&body)?)?;

        if let JsonValue::Object(mut body_obj) = body_val {
            let b64ciphertext = body_obj
                .remove("CiphertextForRecipient")
                .ok_or(anyhow!("Response body is missing 'CiphertextForRecipient'"))?;

            let b64ciphertext = b64ciphertext
                .as_str()
                .ok_or(anyhow!("CiphertextForRecipient is not a string"))?;

            let ciphertext = base64::decode(b64ciphertext)?;
            let plaintext = self.decrypt_cms(&ciphertext)?;

            body_obj["Plaintext"] = json::JsonValue::String(base64::encode(plaintext));
            Ok(json_response(head, JsonValue::Object(body_obj)))
        } else {
            Err(anyhow!("The response body is not a JSON object"))
        }
    }

    async fn handle_forward(&self, req_in: KmsRequestIncoming) -> Result<Response<Full<Bytes>>> {
        let credential = req_in.credential_scope()?;
        credential.validate()?;

        let region = credential.region.to_string();
        let authority = self.config.get_authority(&region);

        let req_out = KmsRequestOutgoing::from_incoming(req_in, authority)?;
        self.send(req_out, &region).await
    }

    async fn send(&self, req: KmsRequestOutgoing, region: &str) -> Result<Response<Full<Bytes>>> {
        let signed = req.sign(self.config.credentials().await?, region)?;

        debug!("Sending Request: {:?}", signed);
        let resp = self.config.client.request(signed).await?;

        let (head, body) = resp.into_parts();
        let body = body.collect().await?;

        Ok(Response::from_parts(head, Full::new(body.to_bytes())))
    }

    fn decrypt_cms(&self, cms: &[u8]) -> Result<Vec<u8>> {
        let content_info = super::pkcs7::ContentInfo::parse_ber(cms)?;
        content_info.decrypt_content(&self.config.keypair.private)
    }
}

#[async_trait]
impl HttpHandler for KmsProxyHandler {
    async fn handle(&self, req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>> {
        debug!("Request: {:?}", req);

        let req_in = KmsRequestIncoming::recv(req).await?;

        // TODO: Check the signature!!!

        let resp = if req_in.is_attesting_action() {
            self.handle_attesting_action(req_in).await
        } else {
            self.handle_forward(req_in).await
        };
        match resp {
            // An error from a handler drops the connection; this one is the
            // caller's to read.
            Err(err) if err.is::<CredentialsUnavailable>() => Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header(hyper::header::CONTENT_TYPE, &X_AMZ_JSON)
                .body(json_body(object! {
                    "__type": "CredentialsUnavailable",
                    "message": err.to_string(),
                }))?),
            resp => resp,
        }
    }
}

// hyper::client::Client implements tower::Service and would make a perfect
// trait but it uses `&mut self` and would require a needless mutex.
#[async_trait]
pub trait HttpClient {
    async fn request(&self, req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>>;
}

#[async_trait]
impl<C> HttpClient for hyper_util::client::legacy::Client<C, Full<Bytes>>
where
    C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
{
    async fn request(&self, req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>> {
        let (head, body) = hyper_util::client::legacy::Client::request(self, req)
            .await?
            .into_parts();
        let body = body.collect().await?;

        Ok(Response::from_parts(head, Full::new(body.to_bytes())))
    }
}

fn body_from_slice(bytes: &[u8]) -> Full<Bytes> {
    Full::new(Bytes::copy_from_slice(bytes))
}

fn json_body(json_val: JsonValue) -> Full<Bytes> {
    let body = json::stringify(json_val);
    body_from_slice(&body.into_bytes())
}

fn bytes_response(head: hyper::http::response::Parts, body: &[u8]) -> Response<Full<Bytes>> {
    Response::from_parts(head, body_from_slice(body))
}

fn json_response(head: hyper::http::response::Parts, json_val: JsonValue) -> Response<Full<Bytes>> {
    Response::from_parts(head, json_body(json_val))
}

fn amz_credential_query(uri: &hyper::Uri) -> Option<String> {
    let q = uri.path_and_query()?.query()?;

    for (k, v) in form_urlencoded::parse(q.as_bytes()) {
        if X_AMZ_CREDENTIAL.eq_ignore_ascii_case(&k) {
            return Some(v.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nsm::StaticAttestationProvider;
    use assert2::assert;
    use aws_credential_types::provider::error::CredentialsError;
    use aws_credential_types::provider::future;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering::SeqCst;
    use pkcs8::DecodePrivateKey;
    use rsa::RsaPrivateKey;

    // Attestation document is passed through verbatim so can test with just random bytes
    const ATTESTATION_DOC: &[u8] = &[
        245, 174, 153, 213, 192, 166, 9, 203, 152, 176, 158, 67, 233, 45, 229, 228,
    ];
    const KEY_ID: &str = "e6ed9116-53d7-11ed-8eee-5b6905c751a7";

    lazy_static! {
        static ref KEYS: JsonValue = object! {
            "Keys": [
                {
                    "KeyArn": "arn:aws:kms:us-east-1:072396882261:key/e6ed9116-53d7-11ed-8eee-5b6905c751a7",
                    "KeyId": KEY_ID,
                }
            ]
        };
    }

    struct Mock;

    #[async_trait]
    impl HttpClient for Mock {
        async fn request(&self, req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>> {
            let action = req.headers().get(&X_AMZ_TARGET).unwrap().to_str().unwrap();

            let authz = req
                .headers()
                .get(hyper::header::AUTHORIZATION)
                .unwrap()
                .to_str()
                .unwrap();

            // Don't validate the signature, just care that it was put it and that it looks like it
            // came from the AWS signing process
            assert!(authz.starts_with("AWS4-HMAC-SHA256 Credential="));

            match action {
                "TrentService.ListKeys" => self.list_keys(req).await,
                "TrentService.Decrypt" => self.decrypt(req).await,
                _ => panic!("unexpected action"),
            }
        }
    }

    impl Mock {
        async fn list_keys(&self, _req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>> {
            Ok(kms_response(KEYS.clone()))
        }

        async fn decrypt(&self, req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>> {
            let (_, body) = req.into_parts();
            let body = body.collect().await?.to_bytes();
            let body = body_as_json(body).await.unwrap();

            // make sure the attestation document has been attached
            let att_doc = body["Recipient"]["AttestationDocument"].as_str().unwrap();
            assert!(att_doc == base64::encode(ATTESTATION_DOC));

            let resp = kms_response(object! {
                "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                "KeyId": KEY_ID,
                "CiphertextForRecipient": crate::proxy::pkcs7::tests::INPUT,
            });

            Ok(resp)
        }
    }

    impl KmsEndpointProvider for Mock {
        fn endpoint(&self, _region: &str) -> String {
            "test.local".to_string()
        }
    }

    fn kms_request(action: &str, body: JsonValue) -> Request<Full<Bytes>> {
        let body_bytes = Bytes::copy_from_slice(json::stringify(body).as_bytes());

        Request::builder()
            .method(Method::POST)
            .uri("/")
            .header(&X_AMZ_TARGET, action)
            .header(hyper::header::CONTENT_TYPE, &X_AMZ_JSON)
            .header(
                hyper::header::AUTHORIZATION,
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/kms/aws4_request, ",
            )
            .body(Full::new(body_bytes))
            .unwrap()
    }

    fn kms_response(body: JsonValue) -> Response<Full<Bytes>> {
        Response::builder()
            .status(hyper::StatusCode::OK)
            .body(json_body(body))
            .unwrap()
    }

    async fn body_as_json(body: Bytes) -> Result<JsonValue> {
        Ok(json::parse(std::str::from_utf8(&body)?)?)
    }

    fn new_test_handler() -> KmsProxyHandler {
        test_handler(CredentialsCache::new(SharedCredentialsProvider::new(
            Credentials::from_keys("TESTKEY", "TESTSECRET", None),
        )))
    }

    fn test_handler(credentials: CredentialsCache) -> KmsProxyHandler {
        let key_der = base64::decode(crate::proxy::pkcs7::tests::PRIVATE_KEY).unwrap();
        let priv_key = RsaPrivateKey::from_pkcs8_der(&key_der).unwrap();

        let config = KmsProxyConfig {
            client: Box::new(Mock),
            credentials,
            keypair: Arc::new(KeyPair::from_private(priv_key)),
            attester: Box::new(StaticAttestationProvider::new(ATTESTATION_DOC.to_vec())),
            endpoints: Arc::new(Mock {}),
        };

        KmsProxyHandler { config }
    }

    /// What `ImdsCredentialsProvider` does: each fetch yields the next scripted
    /// outcome, `Some(expiry)` for a new set or `None` for a failure, which
    /// takes `delay` and yields the last set fetched (or an error before any).
    /// The script runs out into failures.
    #[derive(Debug)]
    struct ImdsLike {
        loads: Arc<AtomicUsize>,
        script: Mutex<VecDeque<Option<Option<SystemTime>>>>,
        last: Mutex<Option<Credentials>>,
        delay: Duration,
    }

    impl ProvideCredentials for ImdsLike {
        fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
        where
            Self: 'a,
        {
            future::ProvideCredentials::new(async move {
                let n = self.loads.fetch_add(1, SeqCst);
                let next = self.script.lock().unwrap().pop_front();
                if !matches!(next, Some(Some(_))) {
                    tokio::time::sleep(self.delay).await;
                }
                let mut last = self.last.lock().unwrap();
                match next {
                    Some(Some(expiry)) => {
                        let creds = Credentials::new(format!("AKID{n}"), "secret", None, expiry, "test");
                        *last = Some(creds.clone());
                        Ok(creds)
                    }
                    Some(None) | None => last.clone().ok_or_else(|| CredentialsError::not_loaded("IMDS is down")),
                }
            })
        }
    }

    const T0: SystemTime = SystemTime::UNIX_EPOCH;
    const LIFETIME: Duration = Duration::from_secs(6 * 3600);

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// A cache over `ImdsLike` with `script`; returns it and its load count.
    fn imds_cache(
        script: &[Option<Option<SystemTime>>],
        delay: Duration,
        timeout: Duration,
    ) -> (CredentialsCache, Arc<AtomicUsize>) {
        let loads = Arc::new(AtomicUsize::new(0));
        let provider = ImdsLike {
            loads: loads.clone(),
            script: Mutex::new(script.iter().cloned().collect()),
            last: Mutex::new(None),
            delay,
        };
        let cache = CredentialsCache::with_timeout(SharedCredentialsProvider::new(provider), timeout);
        (cache, loads)
    }

    #[tokio::test]
    async fn credentials_are_reused_until_the_refresh_window() {
        let script = [Some(Some(T0 + LIFETIME)), Some(Some(T0 + LIFETIME * 2))];
        let (cache, loads) = imds_cache(&script, Duration::ZERO, secs(5));
        for _ in 0..3 {
            cache.get_at(T0).await.unwrap();
        }
        assert!(loads.load(SeqCst) == 1);
        cache.get_at(T0 + LIFETIME - CREDENTIALS_REFRESH_BEFORE - secs(10)).await.unwrap();
        assert!(loads.load(SeqCst) == 1, "a set outside the refresh window was reloaded");
        let creds = cache.get_at(T0 + LIFETIME - CREDENTIALS_REFRESH_BEFORE + secs(10)).await.unwrap();
        assert!(loads.load(SeqCst) == 2, "a set inside the refresh window was not reloaded");
        assert!(creds.access_key_id() == "AKID1");
    }

    /// IMDS down inside the refresh window: the provider hands back the old
    /// set. Concurrent callers share one fetch, keep the old set, and the next
    /// fetch waits `CREDENTIALS_RETRY_AFTER`.
    #[tokio::test]
    async fn a_stale_refresh_serves_the_valid_set_and_backs_off() {
        let (cache, loads) = imds_cache(&[Some(Some(T0 + LIFETIME))], Duration::from_millis(50), secs(5));
        let cache = Arc::new(cache);
        cache.get_at(T0).await.unwrap();
        let t = T0 + LIFETIME - CREDENTIALS_REFRESH_BEFORE + secs(10);
        let started = Instant::now();
        let calls: Vec<_> = (0..8)
            .map(|_| {
                let cache = cache.clone();
                tokio::spawn(async move { cache.get_at(t).await.unwrap() })
            })
            .collect();
        for call in calls {
            assert!(call.await.unwrap().access_key_id() == "AKID0");
        }
        assert!(loads.load(SeqCst) == 2, "eight callers refreshed {} times", loads.load(SeqCst) - 1);
        assert!(started.elapsed() < Duration::from_millis(300), "callers queued: {:?}", started.elapsed());
        cache.get_at(t + CREDENTIALS_RETRY_AFTER - secs(1)).await.unwrap();
        assert!(loads.load(SeqCst) == 2, "refreshed again before CREDENTIALS_RETRY_AFTER");
        cache.get_at(t + CREDENTIALS_RETRY_AFTER + secs(1)).await.unwrap();
        assert!(loads.load(SeqCst) == 3, "never refreshed again");
    }

    /// A refresh that hangs is abandoned, and the valid set is served.
    #[tokio::test]
    async fn a_hung_refresh_serves_the_valid_set() {
        let (cache, _) = imds_cache(&[Some(Some(T0 + LIFETIME))], Duration::from_millis(400), Duration::from_millis(50));
        cache.get_at(T0).await.unwrap();
        let started = Instant::now();
        let creds = cache.get_at(T0 + LIFETIME - secs(60)).await.unwrap();
        assert!(creds.access_key_id() == "AKID0");
        assert!(started.elapsed() < Duration::from_millis(300), "waited {:?} on a hung refresh", started.elapsed());
    }

    /// Past the last set's expiry the cache fails, and without asking again
    /// until `CREDENTIALS_RETRY_AFTER`.
    #[tokio::test]
    async fn an_expired_set_is_never_served() {
        let (cache, loads) = imds_cache(&[Some(Some(T0 + LIFETIME))], Duration::ZERO, secs(5));
        cache.get_at(T0).await.unwrap();
        let err = cache.get_at(T0 + LIFETIME + secs(1)).await.expect_err("an expired set was served");
        assert!(err.to_string().contains("no unexpired instance-role credentials"), "{err}");
        assert!(loads.load(SeqCst) == 2);
        cache.get_at(T0 + LIFETIME + secs(2)).await.expect_err("an expired set was served");
        assert!(loads.load(SeqCst) == 2, "a failed refresh was retried at once");
    }

    #[tokio::test]
    async fn credentials_without_an_expiry_are_not_cached() {
        let (cache, loads) = imds_cache(&[Some(None), Some(None)], Duration::ZERO, secs(5));
        cache.get_at(T0).await.unwrap();
        cache.get_at(T0).await.unwrap();
        assert!(loads.load(SeqCst) == 2);
    }

    /// The caller gets a KMS-shaped error, not a dropped connection.
    #[tokio::test]
    async fn no_credentials_is_a_503_naming_the_cause() {
        let handler = test_handler(imds_cache(&[], Duration::ZERO, secs(5)).0);
        let resp = handler.handle(kms_request("TrentService.ListKeys", object! {})).await.unwrap();
        let (head, body) = resp.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        assert!(head.status == StatusCode::SERVICE_UNAVAILABLE);
        let body = body_as_json(body).await.unwrap();
        assert!(body["message"].as_str().unwrap().contains("no unexpired instance-role credentials"));
    }

    #[test]
    fn test_credential_scope() {
        let req1 = Request::builder()
            .uri("http://kms.us-east-1.amazonaws.com")
            .header(
                hyper::header::AUTHORIZATION,
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/kms/aws4_request, ",
            )
            .body(())
            .unwrap();

        let (head1, _) = req1.into_parts();

        let cred1 = CredentialScope::from_request(&head1).unwrap();
        assert!(cred1.region == "us-east-1");
        assert!(cred1.service == "kms");

        let req2 = Request::builder()
            .uri("http://kms.us-east-1.amazonaws.com?X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fkms%2Faws4_request")
            .body(())
            .unwrap();

        let (head2, _) = req2.into_parts();

        let cred2 = CredentialScope::from_request(&head2).unwrap();
        assert!(cred2.region == "us-east-1");
        assert!(cred2.service == "kms");
    }

    #[tokio::test]
    async fn test_forwarding_action() {
        let handler = new_test_handler();

        let req = kms_request("TrentService.ListKeys", object! {});
        let resp = handler.handle(req).await.unwrap();

        let (head, body) = resp.into_parts();
        let body = body.collect().await.unwrap().to_bytes();

        assert!(head.status == hyper::StatusCode::OK);

        let keys = body_as_json(body).await.unwrap();
        assert!(keys == *KEYS);
    }

    #[tokio::test]
    async fn test_attesting_action() {
        let handler = new_test_handler();

        let req = kms_request(
            "TrentService.Decrypt",
            object! {
               "CiphertextBlob": base64::encode("~~~ ENCRYPTED Hello, World ~~~"),
            },
        );

        let resp = handler.handle(req).await.unwrap();

        let (head, body) = resp.into_parts();
        let body = body.collect().await.unwrap().to_bytes();

        if head.status == hyper::StatusCode::OK {
            let body = body_as_json(body).await.unwrap();
            assert!(body["Plaintext"].as_str().unwrap() == base64::encode("Hello, World"));
            assert!(body["KeyId"].as_str().unwrap() == KEY_ID);
        } else {
            let msg = std::str::from_utf8(&body).unwrap();
            assert!("DUMMY" == msg);
        }
    }
}
