FROM rust:1.58.1

# Copy the project source code from our 
# host machine to the container
COPY . .

# Install the project executable
RUN cargo install --path .

# Configure the environment
ENV FLATTIE_BIND_ADDRESS 0.0.0.0:8080

# Start the server
CMD ["flattie"]