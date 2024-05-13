.phony: build clean dev lint test

build:
	RUST_BACKTRACE=1 cargo build

clean:
	cargo clean

dev: lint
	cargo watch -w src -s 'RUST_BACKTRACE=full cargo run'

lint:
	cargo clippy && cargo fmt -- --check

test:
	RUST_BACKTRACE=1 cargo test
