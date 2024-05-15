.phony: build clean dev lint test

build:
	RUST_BACKTRACE=1 cargo build --verbose

build-release:
	# CGO_ENABLED=0 GOOS=linux cargo build --release
	env GOOS=linux GOARCH=arm64 RUST_BACKTRACE=1 cargo build --release

build-docker: build-release
	docker build -t ${TARGET} .

clean:
	cargo clean

dev: lint
	@$(MAKE) watch

dev-docker:
	@$(MAKE) build-docker
	docker run -p 7400:7400 -it --rm ${TARGET}

watch:
	cargo watch -w ${TARGET}/src -s 'RUST_BACKTRACE=full cargo run --bin ${TARGET}'

lint:
	cargo clippy && cargo fmt -- --check

test:
	RUST_BACKTRACE=1 cargo test --all
