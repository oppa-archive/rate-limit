/// Globally accessible configuration
pub struct Config {
    /// maximum number of requests per IP.
    pub max_request_limit_per_ip: u32,
    /// throttle time for a request after reaching the limit in seconds.
    pub retry_after: u64,
    /// maximum number of degraded requests.
    pub max_graceful_degradation_requests: u32,
    /// maximum number of requests per IP for degraded requests in seconds.
    pub max_retry_after: u64,
    /// reset task interval in seconds.
    pub reset_interval: u64,
    /// exponential backoff configuration.
    pub exponential_backoff: f64,
    /// server port.
    pub port: u16,
}

impl Config {
    pub fn from_env() -> Config {
        let max_request_limit_per_ip = std::env::var("REQUEST_LIMIT_PER_IP")
            .unwrap()
            // .unwrap_or("50".to_string())
            .parse::<u32>()
            .expect("REQUEST_LIMIT_PER_IP must be a number");

        let retry_after = std::env::var("RETRY_AFTER")
            .unwrap()
            // .unwrap_or("300".to_string())
            .parse::<u64>()
            .expect("RETRY_AFTER must be a number");

        let max_graceful_degradation_requests = std::env::var("MAX_GRACEFUL_DEGRADATION_REQUESTS")
            .unwrap()
            // .unwrap_or("5".to_string())
            .parse::<u32>()
            .expect("MAX_GRACEFUL_DEGRADATION_REQUESTS must be a number");

        let max_retry_after = std::env::var("MAX_RETRY_AFTER")
            .unwrap()
            // .unwrap_or("3600".to_string())
            .parse::<u64>()
            .expect("MAX_RETRY_AFTER must be a number");

        let reset_interval = std::env::var("RESET_INTERVAL")
            .unwrap()
            // .unwrap_or("60".to_string())
            .parse::<u64>()
            .expect("RESET_INTERVAL must be a number");

        let exponential_backoff = std::env::var("EXPONENTIAL_BACKOFF")
            .unwrap()
            // .unwrap_or("1.5".to_string())
            .parse::<f64>()
            .expect("EXPONENTIAL_BACKOFF must be a number");

        let port = std::env::var("PORT")
            .unwrap()
            // .unwrap_or("3000".to_string())
            .parse::<u16>()
            .expect("PORT must be a number");

        Config {
            max_request_limit_per_ip,
            retry_after,
            max_graceful_degradation_requests,
            max_retry_after,
            reset_interval,
            exponential_backoff,
            port,
        }
    }
}
