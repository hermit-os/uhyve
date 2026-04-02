#!/usr/bin/env bash

# Get kernels to run for a given architecture, all versions
# If no files are found, leave the array empty.
arch=$(uname -m)
# Get operating system (e.g. for Landlock's --file-isolation)
os=$(uname -o)
shopt -s nullglob
kernels_to_run=(./data/*/${arch}/*)
if (( ${#kernels_to_run[@]} == 0 )); then
    echo "No kernels found."
    echo "This script can only be run in the repository root."
    exit 127
fi

# Print commands before execution for CI output
set -x

# The --file-isolation parameter is only supported in Linux.
# Only then should we invoke Uhyve with it.
if [[ $os == *"Linux"* ]]; then
    run_append=(\
        " --file-isolation none"
        " --file-isolation normal"
        " --file-isolation strict"
    )
else
    run_append=("")
fi

retval=0
for param in "${run_append[@]}"
do
    for kernel in "${kernels_to_run[@]}"
    do
        cargo run $kernel --stats $param
        # Store exit code of command above.
        status=$?
        # If `cargo run`'s exit code is an error, we store that in `retval` to
        # cause a CI failure only after all configurations are run.
        if [[ "$status" != 0 ]]; then
            retval=$status
        fi
    done
done

exit $retval
