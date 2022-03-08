# This file makes use of multistage Docker 
# builds: https://docs.docker.com/develop/develop-images/multistage-build/

FROM rust:1.58.1-alpine as builder
# Install static libs and C tooling 
# needed for compilation
RUN apk --no-cache add gcc g++ openssl-dev
# Create a folder for installing the 
# executable
WORKDIR /project
# Copy the project source code from our 
# host machine to the container
COPY . .
# Build the project executable
RUN cargo build --release

FROM alpine:3.15.0
WORKDIR /project
# Copy the executable from the build 
# stage into this one
COPY --from=builder /project/target/release/flattie ./
COPY --from=builder /project/static ./static
# Configure the environment. We use build args 
# and envars together to allow both build and 
# run time configuration
ARG ENV_FLATTIE_LOG_LEVEL=flattie=trace
ENV FLATTIE_LOG_LEVEL=${ENV_FLATTIE_LOG_LEVEL}

ARG ENV_FLATTIE_SQL_CONNECTION_URL=sqlite::memory:
ENV FLATTIE_SQL_CONNECTION_URL=${ENV_FLATTIE_SQL_CONNECTION_URL}

ARG ENV_FLATTIE_BIND_ADDRESS=0.0.0.0:8080
ENV FLATTIE_BIND_ADDRESS=${ENV_FLATTIE_BIND_ADDRESS}
# Start the server
CMD ["./flattie"]