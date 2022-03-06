# flattie

Flattie is the fastest server boilerplate on the web. Use it when response time is of the essence. It should feel like Rails or Django, but Rusty and a tad less opinionated.

## Configuration

By default, Flattie uses environment variables to control how it behaves. The variables it understands are:

```
FLATTIE_LOG_LEVEL=flattie=trace
```

Default: `flattie=trace`

This variable controls the server's logging verbosity. Verbosity values follow the levels defined by Rust's [log crate](https://docs.rs/log/0.4.6/log/#use). If you only want Flattie-specific logs, set the value to `flattie=my-log-level` (e.g. `FLATTIE_LOG_LEVEL=flattie=info`). If you're also okay with receiving Actix-specific logs, set the value to `my-log-level` without prefixing it with anything (e.g. `FLATTIE_LOG_LEVEL=debug`).

```
FLATTIE_BIND_ADDRESS=localhost:8080
```

Default: `localhost:8080`

This variable controls the server's bind address. It's defined in `IP:PORT` format.

```
FLATTIE_SQL_CONNECTION_URL=mysql://...
```

Default: `sqlite::memory:` (in-memory SQLite database)

This variable determines which SQL database the server will connect to for database operations. At the moment, only SQLite and MySQL are supported, but other flavors can be supported by adding their respective `sqlx` features to this project's `Cargo.toml` ([Read more](https://github.com/launchbadge/sqlx)).

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

Flattie spiders are known to have one of the fastest strikes on prey among all spiders. They have some of the fastest response times on the literal web!

Copyright (C) 2021 Gerald Nash
