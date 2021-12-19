# flattie

Flattie is the fastest server boilerplate on the web. Use it when response time is of the essence. It should feel like Rails or Django, but Rusty and a tad less opinionated.

## Unit Tests

To run unit tests:

```
cargo test
```

## Local Development

To build and run a development version of the server:

```
cargo run
```

## Build for Release

To build a release binary:

```
cargo build --release
```

Note that you can set the optimization levels for release builds with the `opt-level` value in `Cargo.toml`. More details can be found in [the Cargo reference](https://doc.rust-lang.org/cargo/reference/profiles.html#opt-level).

### Fun Fact

Flattie spiders are known to have one of the fastest strikes on prey among all spiders. They're some of the fastest things on the literal web!

Copyright (C) 2021 Gerald Nash
