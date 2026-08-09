# Justfile for Rust project using Cargo

all: fmt clippy-fix

# Build the project with all features enabled in release mode
build:
    cargo build --workspace --release --all-features

# Check the project for compilation errors without producing binaries
check:
    cargo check --workspace --all-features

# Update dependencies to their latest compatible versions
update:
    cargo update

# Run the project with all features enabled in release mode
run:
    cargo run --release --all-features

# Run all tests with all features enabled
test:
    cargo test --workspace --all-features

# Supply-chain policy (also CI security.yml)
deny:
    cargo deny check

# Ultimate CLI coverage matrix (real binary; ~1–3 min)
test-ultimate:
    cargo test -p ks-cli --test e2e_ultimate -- --nocapture

# All ks-cli real-binary e2e (json + security + multidevice + ultimate)
test-e2e:
    cargo test -p ks-cli --test json --test e2e_security --test multidevice --test e2e_ultimate -- --nocapture

# Full automated gates + ultimate matrix
test-all: test test-ultimate deny

# Run benchmarks with all features enabled
bench:
    cargo bench --all-features

# Run Clippy linter with nightly toolchain (check only, for CI)
# Uses workspace lints from Cargo.toml
clippy:
    cargo +nightly clippy --workspace \
        --all-targets \
        --all-features \
        -- -D warnings

# Run Clippy linter with auto-fix (for development)
clippy-fix:
    cargo +nightly clippy --workspace \
        --fix \
        --all-targets \
        --all-features \
        --allow-dirty \
        --allow-staged \
        -- -D warnings

# Format the code using rustfmt with nightly toolchain
fmt:
    cargo +nightly fmt

# Generate documentation for all crates and open it in the browser
doc:
    cargo +nightly doc --all-features --no-deps --open
