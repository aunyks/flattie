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

## Local Development (Hot Reloading)

In some cases, especially when editing frontend code, having the server reload once a file has changed can save lots of time. To do so with flattie, install `cargo-watch`. Note: this will install `cargo-watch` globally on your machine, not just for this project.

```
cargo install cargo-watch
```

Then, run the following command to start the server and have it automatically reload when _any_ file is changed.

```
cargo watch -x 'run'
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
