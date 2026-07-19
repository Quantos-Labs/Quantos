.PHONY: build build-release test test-consensus clippy fmt fmt-check fuzz-build fuzz-run fuzz-clean docker-build docker-reproducible clean

# Reproducible build environment variables
SOURCE_DATE_EPOCH ?= 0
RUSTFLAGS_REPRO := -C remap-path-prefix=$(CURDIR)=

# Default target
all: build-release

## Build (debug)
build:
	cargo build --locked --workspace

## Build (release, reproducible)
build-release:
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
	RUSTFLAGS="$(RUSTFLAGS_REPRO)" \
	cargo build --release --locked --frozen --bin quantos --bin quantos-cli

## Run library tests
test:
	cargo test --lib --workspace --locked

## Run adversarial consensus tests only
test-consensus:
	cargo test --lib --locked -- consensus::adversarial_tests

## Clippy lints
clippy:
	cargo clippy --workspace --all-targets -- -D warnings

## Format code
fmt:
	cargo fmt --all

## Check formatting without modifying
fmt-check:
	cargo fmt --all -- --check

## Build fuzz targets (requires nightly)
fuzz-build:
	cd L1 && cargo +nightly fuzz build

## Run all fuzz targets for N seconds (default 60)
fuzz-run:
	@for target in fuzz_tx_deserialize fuzz_tx_prefilter fuzz_network_message fuzz_rlp_decode fuzz_chain_proof_json; do \
		echo "=== Fuzzing $$target ===" ; \
		cd L1 && cargo +nightly fuzz run $$target -- -max_total_time=$(FUZZ_SECONDS) -max_len=4096 ; \
		cd .. ; \
	done

## Clean fuzz corpus and artifacts
fuzz-clean:
	rm -rf L1/fuzz/artifacts L1/fuzz/corpus

## Build Docker image
docker-build:
	docker build -t quantos:latest -f L1/Dockerfile .

## Build Docker image (reproducible, no cache)
docker-reproducible:
	docker build --no-cache \
		--build-arg GIT_SHA=$$(git rev-parse --short HEAD) \
		--build-arg GIT_TAG=$$(git describe --tags --always --dirty 2>/dev/null || echo unknown) \
		--build-arg BUILD_DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ) \
		-t quantos:reproducible \
		-f L1/Dockerfile .

## Clean build artifacts
clean:
	cargo clean
	rm -rf L1/fuzz/artifacts L1/fuzz/corpus
