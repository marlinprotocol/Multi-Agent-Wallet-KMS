FROM rust:alpine AS builder
WORKDIR /usr/src/app
COPY . .
RUN apk add musl-dev
RUN cargo build --release

FROM alpine
COPY --from=builder /usr/src/app/target/release/signing-server /usr/local/bin/signing-server
CMD ["signing-server"]