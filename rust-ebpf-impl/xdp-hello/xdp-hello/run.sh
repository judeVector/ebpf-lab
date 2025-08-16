#!/bin/bash
# You can choose to remove the --quiet flag to see the warnings 
RUST_LOG=info cargo run --release --quiet --config 'target."cfg(all())".runner="sudo -E"'