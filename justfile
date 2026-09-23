build:
    cargo build

ctrl *ARGS:
    cargo run --bin weirctrl {{ ARGS }}

ctrl-dev:
    cargo run --bin weirctrl cert-gen --san 127.0.0.1 --cert-dir certs
    cargo run --bin weirctrl serve --addr 127.0.0.1:8443 --cert-dir certs
