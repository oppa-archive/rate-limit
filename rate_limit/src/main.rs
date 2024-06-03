use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use axum_client_ip::{InsecureClientIp, SecureClientIp, SecureClientIpSource};
use chrono::DateTime;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use tokio::time::interval;

mod config;
pub use self::config::Config;

/// RateLimitError is an enum that represents the rate limit errors.
enum RateLimitError {
    /// RateLimitExceeded is an error that is returned when the rate limit is exceeded.
    RateLimitExceeded,
}

/// RateLimit is a struct that holds the rate limit data for a given ip address.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RateLimit {
    ip_address: String,
    /// limit is the maximum request that can be made in a given time frame.
    limit: u32,
    /// remaining is the number of requests that can be made before the rate limit is hit.
    remaining: u32,
    /// reset is a unix timestamp of the time the rate limit was last reset.
    issued_at: u64,
    /// retry_after is the number of seconds until the rate limit resets, it's a TTL.
    retry_after: u64,
    /// retry_count is the number of times the rate limit has been hit.
    retry_count: u32,
}

/// RateLimitStore is a hashmap that stores the rate limit data for each ip address.
/// The key is the ip address and the value is the RateLimit struct.
type RateLimitStore = Arc<Mutex<HashMap<String, RateLimit>>>;

lazy_static! {
    /// RATE_LIMIT_STORE is a global hashmap that stores the rate limit data for each ip address.
    static ref RATE_LIMIT_STORE: RateLimitStore = Arc::new(Mutex::new(HashMap::new()));
    /// CONFIG is a global configuration struct that holds the configuration values.
    static ref CONFIG: Config = Config::from_env();

}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> Response {
        let response = match self {
            RateLimitError::RateLimitExceeded => {
                let mut response = Response::new(Body::from("Rate limit exceeded"));

                *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                response.headers_mut().insert(
                    header::RETRY_AFTER,
                    HeaderValue::from_str(&CONFIG.retry_after.clone().to_string()).unwrap(),
                );
                response
                    .headers_mut()
                    .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));

                response
            }
        };

        response
    }
}

impl std::fmt::Display for RateLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "RateLimit {{ ip_address: {}, limit: {}, remaining: {}, issued_at: {}, expires_at: {} }}",
            self.ip_address,
            self.limit,
            self.remaining,
            DateTime::from_timestamp(self.issued_at as i64, 0).expect("Failed to convert timestamp to DateTime").to_rfc3339(),
            DateTime::from_timestamp(self.issued_at as i64 + self.retry_after as i64, 0).expect("Failed to convert timestamp to DateTime").to_rfc3339(),
        )
    }
}

impl IntoResponse for RateLimit {
    fn into_response(self) -> Response {
        let response_body = serde_json::to_string(&self)
            .map_err(|e| {
                eprintln!("Failed to serialize RateLimit to JSON: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })
            .unwrap();

        let mut response = Response::new(Body::from(response_body));

        *response.status_mut() = StatusCode::OK;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        response
    }
}

impl RateLimit {
    /// new is a constructor for the RateLimit struct.
    /// It takes an ip address and returns a new RateLimit struct with the default values.
    fn new(ip_address: String) -> RateLimit {
        RateLimit {
            ip_address,
            limit: CONFIG.max_request_limit_per_ip,
            remaining: CONFIG.max_request_limit_per_ip,
            issued_at: RateLimit::current_timestamp(),
            retry_after: CONFIG.retry_after,
            retry_count: 0,
        }
    }

    /// is_expired is a method that checks if the rate limit data is expired.
    /// It returns true if the rate limit data is expired and false if it's not.
    fn is_expired(&self) -> bool {
        RateLimit::current_timestamp() > self.issued_at + self.retry_after
    }

    /// reset_if_expired is a method that resets the rate limit data if it's expired.
    fn reset_if_expired(&mut self) {
        if self.is_expired() {
            self.remaining = self.limit;
            self.issued_at = RateLimit::current_timestamp();
            self.retry_after = CONFIG.retry_after;
            self.retry_count = 0;
        }
    }

    /// consume_request is a method that consumes a request from the rate limit.
    fn consume_request(&mut self) -> bool {
        self.reset_if_expired();

        if self.remaining > 0 {
            self.remaining -= 1;
            true
        } else {
            // Apply exponential backoff: double the retry interval
            if self.retry_count == CONFIG.max_graceful_degradation_requests
                && self.retry_after < CONFIG.max_retry_after
            {
                self.retry_after = (self.retry_after as f64 * CONFIG.exponential_backoff) as u64;
                // Cap the retry interval
                if self.retry_after > CONFIG.max_retry_after {
                    self.retry_after = CONFIG.max_retry_after;
                }
            }
            // Max retry count reached, gracefully degrade
            if self.retry_count < CONFIG.max_graceful_degradation_requests {
                self.retry_count += 1;
            }

            false
        }
    }

    /// current_timestamp is a helper function that returns the current unix timestamp.
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// reset_rate_limits_task is a background task that runs every DEFAULT_RESET_TASK_INTERVAL
    /// seconds and resets the rate limits.
    async fn reset_rate_limits_task() {
        let mut interval = interval(Duration::from_secs(CONFIG.reset_interval));

        loop {
            interval.tick().await;

            let mut rate_limit_store = RATE_LIMIT_STORE.lock().unwrap();
            for rate_limit in rate_limit_store.values_mut() {
                println!("checking - {:?}", rate_limit);

                rate_limit.reset_if_expired();
            }
        }
    }
}

/// handle_rate_limit is a handler that takes the request ip address and lookup up the rate-limit hashmap
/// finds the rate-limit for the ip address and returns the rate limit data.
async fn handle_request(InsecureClientIp(ip): InsecureClientIp) -> Response<Body> {
    let ip_address = ip.to_string();
    let mut rate_limit_store = RATE_LIMIT_STORE.lock().unwrap();

    let rate_limit = rate_limit_store
        .entry(ip_address.clone())
        .or_insert_with(|| RateLimit::new(ip_address.clone()));

    if rate_limit.consume_request() {
        println!("{}", rate_limit);

        let mut response = axum::response::Response::new(Body::from("OK"));

        *response.status_mut() = StatusCode::OK;
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));

        response
    } else {
        RateLimitError::RateLimitExceeded.into_response()
    }
}

/// handle_status is a handler that takes the request ip address and lookup up the rate-limit hashmap
/// finds the rate-limit for the ip address and returns the rate limit data.
async fn handle_status(InsecureClientIp(ip): InsecureClientIp) -> axum::response::Response<Body> {
    let ip_address = ip.to_string();
    let mut rate_limit_store = RATE_LIMIT_STORE.lock().unwrap();

    let rate_limit = rate_limit_store
        .entry(ip_address.clone())
        .or_insert_with(|| RateLimit::new(ip_address.clone()));

    println!("{}", rate_limit);

    rate_limit.clone().into_response()
}

/// root is a handler that takes the request ip address and returns a string response.
async fn root(insecure_ip: InsecureClientIp, secure_ip: SecureClientIp) -> String {
    format!("ping! - {insecure_ip:?} {secure_ip:?}")
}

#[derive(Debug, Clone)]
struct Svc {}

impl hyper::service::Service<::hyper::Request<hyper::body::Incoming>> for Svc {
    type Response = hyper::Response<Body>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        // Box::pin(async {})

        // let addr = SocketAddr::from(([0, 0, 0, 0], CONFIG.port));
        // println!("Listening on http://{}", addr);

        // let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        // axum::serve(
        //     listener,
        //     app.into_make_service_with_connect_info::<SocketAddr>(),
        // )
        // .await
        // .unwrap();

        let response = hyper::Response::new(Body::from("Hello, World!"));
        Box::pin(async { Ok(response) })

        // let app = Router::new()
        //     .route("/", get(root))
        //     .route("/status", get(handle_status))
        //     .route("/request", post(handle_request))
        //     .layer(SecureClientIpSource::ConnectInfo.into_extension());

        // app.into_make_service_with_connect_info::<SocketAddr>();
        // app.as_service();

        // Box::pin(async { Ok(app) })
        // Box::pin(app)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    // tokio::spawn(RateLimit::reset_rate_limits_task());

    let addr = SocketAddr::from(([0, 0, 0, 0], CONFIG.port));
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    println!("Listening on http://{}", addr);

    // let app = Router::new()
    //     .route("/", get(root))
    //     .route("/status", get(handle_status))
    //     .route("/request", post(handle_request))
    //     .layer(SecureClientIpSource::ConnectInfo.into_extension());

    // let addr = SocketAddr::from(([0, 0, 0, 0], CONFIG.port));
    // println!("Listening on http://{}", addr);

    // let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    // axum::serve(
    //     listener,
    //     app.into_make_service_with_connect_info::<SocketAddr>(),
    // )
    // .await
    // .unwrap();

    let svc = Svc {};

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        let svc_clone = svc.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new().serve_connection(io, svc_clone).await {
                eprintln!("an error occurred; error = {:?}", err);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_rate_limit() {
        let ip_address = "127.0.0.1".to_string();
        let rate_limit = RateLimit::new(ip_address.clone());

        assert_eq!(rate_limit.ip_address, ip_address);
        assert_eq!(rate_limit.limit, CONFIG.max_request_limit_per_ip.clone());
        assert_eq!(
            rate_limit.remaining,
            CONFIG.max_request_limit_per_ip.clone()
        );
        assert!(rate_limit.issued_at > 0);
        assert_eq!(rate_limit.retry_after, CONFIG.retry_after.clone())
    }

    #[test]
    fn test_rate_limit_is_expired() {
        let mut rate_limit = RateLimit::new("127.0.0.1".to_string());

        assert!(!rate_limit.is_expired());

        rate_limit.issued_at = RateLimit::current_timestamp() - 400;

        assert!(rate_limit.is_expired());
    }

    #[test]
    fn test_reset_if_expired() {
        let mut rate_limit = RateLimit::new("127.0.0.1".to_string());

        rate_limit.issued_at = RateLimit::current_timestamp() - 400;
        rate_limit.reset_if_expired();

        assert_eq!(rate_limit.remaining, CONFIG.max_request_limit_per_ip);
        assert!(!rate_limit.is_expired());
    }

    #[test]
    fn test_consume_request() {
        let mut rate_limit = RateLimit::new("127.0.0.1".to_string());

        for _ in 0..CONFIG.max_request_limit_per_ip {
            assert!(rate_limit.consume_request());
        }

        assert!(!rate_limit.consume_request());
    }
}
