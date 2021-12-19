# /src

`main.rs` - The main entrypoint of the binary. It imports handler functions from other modules and routes requests to them. Here, we can define shared server state or behavior. Logging, global state, compression, and other behaviors can be configured here.
`marketing.rs` - The marketing module. Request handler functions in this module serve static marketing pages like the homepage, about page, etc.
