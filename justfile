alias t := test
alias s := start
alias las := launch_aux_services
alias has := halt_aux_services

export FLATTIE_SQL_CONNECTION_URL := "postgresql://username:password@127.0.0.1:5432/database"

default:
  just --list

# Start auxiliary services, such as SQL database and SMTP server
launch_aux_services:
  docker compose up -d --wait --quiet-pull

# Stop auxiliary services, such as SQL database and SMTP server
halt_aux_services:
  docker compose down --remove-orphans

test: launch_aux_services && halt_aux_services
  -cargo test

serve_files:
  deno run --allow-net --allow-read /file_server.ts

start:
  cargo run