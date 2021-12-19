# /static

This is where static files that can be requested by any HTTP client are stored. Place CSS, JavaScript, images, and other miscellaneous static content here.

If you build your application as a binary, this directory must be located in the same directory as the binary. The structure should look something like this:

```
├── flattie-binary
├── static
│   └── css
│       ├── flattie.css
│       └── pico.min.css
```

Note: Delete this file before deploying to production!
