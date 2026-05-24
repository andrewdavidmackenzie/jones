---
layout: default
title: "JP008: Expect Err"
---

# JP008: Expect Err

> **Note**: `expect()` on `Err` was previously JP009. It is now reported under JP008, as `[JP008/expect: expect_failed]`.

**Severity**: High
**Category**: Option/Result Handling

## Description

Calling `.expect()` on a `Result` that contains an `Err` variant.

## Example

```rust
fn load_config() -> Config {
    let file = File::open("app.conf")
        .expect("Failed to open config file");  // JP008
    serde_json::from_reader(file)
        .expect("Failed to parse config")        // JP008
}
```

## How to Avoid

See [JP006 - Unwrap Err](/panics/JP007-unwrap-err) for detailed solutions.

### Quick fix: propagate with `?`

```rust
fn load_config() -> Result<Config, Box<dyn Error>> {
    let file = File::open("app.conf")?;
    let config = serde_json::from_reader(file)?;
    Ok(config)
}
```

## Jonesy Output

```text
 --> src/lib.rs:3:10 [JP008/expect: expect_failed]
     = help: Use if let, match, unwrap_or, or ? operator instead
```

## Related

- [JP006 - Unwrap Err](/panics/JP007-unwrap-err): `unwrap()` without message (previously JP007)
- [JP008 - Expect None](/panics/JP008-expect-none): `expect()` on `Option::None`
