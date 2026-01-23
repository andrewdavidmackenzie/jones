all: clippy examples run

clippy:
	cargo clippy --tests --no-deps --all-features --all-targets

.PHONY: examples
examples:
	cargo build --example array_access
	cargo build --example perfect
	cargo build --release --example array_access
	cargo build --release --example perfect

run: examples
	cargo run -- --examples --debug
	cargo run -- --examples --release