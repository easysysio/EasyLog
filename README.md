# EasyLog
Log analyzer — an Axum web service for ingesting and analyzing logs.

## Run

```sh
cargo run
```

The server listens on `http://0.0.0.0:3000`.

```sh
curl localhost:3000/health   # -> ok
curl localhost:3000/         # -> EasyLog — Log analyzer
```

Set `RUST_LOG=debug` for verbose logging.
