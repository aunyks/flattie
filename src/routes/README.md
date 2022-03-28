# /src/routes

The module for request handlers. It's recommended that handlers are grouped into files or submodules corresponding to their use or category.

`mod.rs` - An idiomatic file for re-exporting submodules of `routes` to other modules within the project. This file is needed so that `/src/main.rs` can properly import request handlers. This file must be updated whenever a submodule is created or removed.

`marketing.rs` - The marketing module. Request handler functions in this module serve static marketing pages like the homepage, about page, etc.

`constants.rs` - Miscellaneous constants. These could arguably be brought in via a config file or envars, but I like them here.

`auth.rs` - Authentication (signup, login, logout) routes.

`app.rs` - Routes to be hidden behind an authenticaiton wall. These exist to help showcase the authentication flows.
