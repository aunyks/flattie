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

FROM alpine:latest
WORKDIR /project
# Copy the executable from the build 
# stage into this one
COPY --from=builder /project/target/release/flattie ./
COPY --from=builder /project/static ./static
# Configure the environment
ENV FLATTIE_BIND_ADDRESS 0.0.0.0:8080
# Start the server
CMD ["./flattie"]