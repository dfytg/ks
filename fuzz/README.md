# Fuzz harness (optional)

This directory is a **placeholder**. There is no `cargo-fuzz` crate here yet
(workspace `exclude = ["fuzz"]`).

## What runs in CI today

Stable soak tests inside `crates/ks` (random inputs, no panic):

- `envelope::tests::soak_random_inputs_do_not_panic`
- `generations::tests::soak_random_parse_does_not_panic`

## Optional libFuzzer

Requires nightly + `cargo-fuzz`. Wire targets yourself against the library
entry points (feature `fuzzing` on `ks`):

```rust
ks::fuzzing::fuzz_envelope_unwrap(data);
ks::fuzzing::fuzz_generations_parse(data);
```

Do not run `cargo fuzz` against this empty directory until a real fuzz crate
and targets are added.
