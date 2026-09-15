build:
    cargo build

ctrl *ARGS:
    cargo run --bin weirctrl {{ ARGS }}

ctrl-test:
    cargo run --bin weirctrl serve --addr 127.0.0.1:8443 --san weir --cert-dir certs
