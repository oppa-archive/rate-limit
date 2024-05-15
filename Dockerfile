FROM alpine:latest

COPY ./target/x86_64-unknown-linux-musl/release/rate_limit /rate_limit

# Expose the rate_limit service port
EXPOSE 7400

ENTRYPOINT ["/rate_limit"]
