---
layout: default
title: "JP006: Unwrap Err"
---

# JP006: Unwrap Err

> **Note**: `unwrap()` on `Err` was previously JP007. It is now reported under JP006, as `[JP006/unwrap: unwrap_failed]`.

**Severity**: High
**Category**: Option/Result Handling

## Description

Calling `.unwrap()` on a `Result` that contains an `Err` variant.

## Example

```rust
fn read_config() -> Config {
    let content = std::fs::read_to_string("config.toml").unwrap();  // JP006
    parse_config(&content)
}
```

## Why It Happens

- I/O operation fails (file not found, permission denied)
- Network request fails
- Parse error on invalid input
- External service unavailable

## How to Avoid

### Propagate with `?`

```rust
fn read_config() -> Result<Config, Box<dyn Error>> {
    let content = std::fs::read_to_string("config.toml")?;
    Ok(parse_config(&content)?)
}
```

### Handle the error explicitly

```rust
fn read_config() -> Config {
    match std::fs::read_to_string("config.toml") {
        Ok(content) => parse_config(&content),
        Err(e) => {
            eprintln!("Warning: Could not read config: {e}");
            Config::default()
        }
    }
}
```

### Use `unwrap_or_else`

```rust
let content = std::fs::read_to_string("config.toml")
    .unwrap_or_else(|_| String::from("default = true"));
```

### Convert to Option

```rust
let content = std::fs::read_to_string("config.toml").ok();
```

## Jonesy Output

```text
 --> src/lib.rs:2:16 [JP006/unwrap: unwrap_failed]
     = help: Use if let, match, unwrap_or, or ? operator instead
```

## Related

- [JP006 - Unwrap None](/panics/JP006-unwrap-none): `unwrap()` on `Option::None`
- [JP008 - Expect Err](/panics/JP009-expect-err): `expect()` on `Err` (previously JP009)
