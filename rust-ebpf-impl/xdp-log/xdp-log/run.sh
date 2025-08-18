#!/bin/bash
# You can choose to add the --quiet flag to stop the warnings 
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'