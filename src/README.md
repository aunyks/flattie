# /src

`main.rs` - The main entrypoint of the binary. It imports handler functions from other modules and routes incoming requests to them. Here, we can define shared server state or behavior. Logging, global state, compression, and other behaviors can be configured here.

`/routes` - The module for request handlers. It's recommended that handlers are grouped into files or submodules corresponding to their use or category. For example, handlers for marketing pages like the homepage, about page, contact page, etc are located in `/routes/marketing.rs`.
