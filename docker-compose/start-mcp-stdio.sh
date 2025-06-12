#!/bin/bash

# This script should be in the same directory as the compose.yaml
cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null

trap "docker compose down" EXIT # Make sure docker containers don't remain if error occurs

docker compose up --detach

# Wait for all containers in the compose is running
all_up() {
    ! docker container inspect -f '{{.State.Running}}' \
        $(docker compose ps --all --quiet) |
        grep --invert-match -e 'true'
}

MAX_POLLS=10
POLL_INTERVAL_S=1
for (( i=0; i<MAX_POLLS; i++ )); do
    if all_up; then
        docker compose attach mcp

        # Stop container after attachment terminates
        docker compose stop
        exit 0
    fi
    sleep "$POLL_INTERVAL_S"
done

# Not up after 10s
docker compose down
echo "Error: Containers not up and running after $(( MAX_POLLS * POLL_INTERVAL_S ))s" >&2
echo "       Cleaning up; Removing containers..." >&2
exit 1

