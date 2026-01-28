all: clippy examples run

clippy:
	cargo clippy --tests --no-deps --all-features --all-targets

.PHONY: examples
examples:
	cargo build --example array_access
	dsymutil ./target/debug/examples/array_access -o ./target/debug/examples/array_access.dSYM 2>&1
	cargo build --example perfect
	cargo build --example panic
	cargo build --example oom
	dsymutil ./target/debug/examples/oom -o ./target/debug/examples/oom.dSYM 2>&1
	cargo build --release --example array_access
	cargo build --release --example perfect
	cargo build --release --example panic
	cargo build --release --example oom

run: examples
	cargo run -- --examples --debug
	cargo run -- --examples --release