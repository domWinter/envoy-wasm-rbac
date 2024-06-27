alias b := build

build:
	cargo build --target wasm32-wasi --release

test:
    cargo test