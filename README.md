# flattie

Flattie is the fastest server boilerplate on the web. Use it when response time is of the essence. It should feel like Rails or Django, but Rusty and a tad less opinionated.

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

## Debugging with Visual Studio Code

To add breakpoints and pause and inspect execution using [VS Code](https://code.visualstudio.com/), you must have installed the [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) extension and the [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=matklad.rust-analyzer) or [Rust](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust) extension (I prefer `rust-analyzer`).

To debug the project, first build it with `cargo build` or the "Build Flattie" build task. Then, with your breakpoints already inserted, select from the navbar at the top of the screen: "Run" > "Start Debugging".

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

## Testing

**Unit Tests**

To run unit tests:

```
cargo test
```

**End-to-End Tests**

To run E2E tests:

```
docker compose --file test/e2e/docker-compose.yaml up --build --abort-on-container-exit
```

## Docker

For enhanced portability and consistency, you can build this project into a Docker image using the `Dockerfile`.

To build the flattie image with default configuration, run:

```

docker build -t flattie .

```

To run it with default configuration, run:

```

docker run -p 8080:8080 --rm flattie

```

You can configure flattie at build _or_ run time.

**Build Time Config**
To configure flattie at build time, specify environment variables as build arguments prefixed with `ENV_`. For example, if you'd like to set the log level at build time you can run:

```

docker build -t flattie . --build-arg ENV_FLATTIE_LOG_LEVEL=flattie=trace

```

You can then run the container normally, as the environment variables will already be configured.

**Run Time Config**
To configure flattie at run time, specify environment variables as normal. For example, if you'd like to set the log level at run time you can run:

```

docker run -p 8080:8080 --rm -e "FLATTIE_LOG_LEVEL=trace" flattie

```

### Fun Fact

Flattie spiders are known to have one of the fastest strikes on prey among all spiders. They have some of the fastest response times on the literal web!

Copyright (C) 2021 Gerald Nash
