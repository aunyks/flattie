# /src/models

Rusty abstractions for things useful to the application. These should try their best to provide straightforward interfaces to models and should hide SQL queries and other miscellaneous API calls from a customer.

`mod.rs` - An idiomatic file for re-exporting submodules of `models` to other modules within the project. This file is needed so that other modules can import this module and its submodules for use. This file must be updated whenever a submodule is created or removed.

`user.rs` - The user module. This module provides easy-to-use abstractions around a set of SQL tables related to a user of an application. It assumes that the provided SQL connection has tables defined in `/migrations/create-user-tables.sql`.

See the `impl User` definition within the file to see the functions that it exports. See tests within the file for example uses of the `User` structure and related functions.
