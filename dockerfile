# Build stage
FROM rust:1.76-alpine as builder

# Needed to build libsecp256k1
RUN apk add --no-cache build-base sqlite sqlite-dev

WORKDIR /usr/src/dnsseedrs

COPY . .

# Flags needed to link to dynamic libraries: https://github.com/rust-lang/rust/issues/115430#issuecomment-1744767352
ENV RUSTFLAGS="-Ctarget-feature=-crt-static"
RUN cargo install --path .

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates cjdns i2pd libgcc sqlite sqlite-dev tor

WORKDIR /usr/bin

COPY --from=builder /usr/local/cargo/bin/dnsseedrs /usr/bin/dnsseedrs

# Use to mount config and/or db
RUN mkdir /data
VOLUME /data

CMD ["/usr/bin/dnsseedrs"]

# Expose DNS port
EXPOSE 53
