all: clippy run

clippy:
	cargo clippy --tests --no-deps --all-features --all-targets

run:
	cargo run -- --examples --debug
	cargo run -- --examples --release