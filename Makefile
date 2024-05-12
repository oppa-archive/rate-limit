.phony: build check dev test

build:
	RUST_BACKTRACE=1 cargo build

lint:
	cargo clippy && cargo fmt -- --check

clean:
	cargo clean

dev: lint
	# cargo watch -w src -x 'cargo clippy && run'
	cargo watch -w src -s 'RUST_BACKTRACE=full cargo run'

test:
	RUST_BACKTRACE=1 cargo test
