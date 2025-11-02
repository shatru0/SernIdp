# A sample justfile
# Use `just <recipe>` to run a task.

# Default recipe (runs if you type only `just`)
default: build

# Variables
project_name := "my_app"
build_dir := "build"

# Simple recipe
build:
    echo "Building {{project_name}}..."
    mkdir -p {{build_dir}}
    cargo build --release --target-dir {{build_dir}}

# Recipe with arguments
run name:
    echo "Running task for {{name}}..."
    ./{{build_dir}}/{{project_name}} --user {{name}}

# Recipe depending on another
deploy: build
    echo "Deploying {{project_name}}..."
    scp {{build_dir}}/{{project_name}} user@server:/opt/{{project_name}}

# Shell commands can span multiple lines
clean:
    echo "Cleaning build artifacts..."
    rm -rf {{build_dir}}
    echo "Clean complete."

# Environment variables
set-env:
    export DATABASE_URL="postgres://localhost/devdb"
    echo "Environment set."

# Recipe with a shebang (runs in its own shell)
script:
    #!/usr/bin/env bash
    echo "This runs in Bash!"
    date
