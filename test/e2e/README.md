# Flattie End-to-End Tests

Here are tests meant to mimic high level user behavior with your flattie project.

You should run them via Docker using the following commands:

If this directory is your current working directory, run:

```
docker compose up --build --abort-on-container-exit
```

If the project root directory is your current working directory, run:

```
docker compose --file test/e2e/docker-compose.yaml up --build --abort-on-container-exit
```
