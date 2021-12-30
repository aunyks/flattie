# /migrations

This is where SQL migrations are stored. Files that are used to setup and edit databases.

`create-user-tables.sql` - Minimum viable definitions of tables related to a user of an application. This file assumes user passwords are optional, a user may have more than one email, a user may have more than one Ethereum address, and the only property that a user _must_ have is a username (a user may have 0 emails or Ethereum addresses setup).

If your application cannot make these assumptions, you must edit this file and `/src/models/user.rs` accordingly.
