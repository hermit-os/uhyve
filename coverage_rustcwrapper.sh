#!/usr/bin/env bash

# Invoked by cargo
# The first argument will be the path to rustc
# The crate name is the argument after --crate-name

# This searches for --crate-name in the parameters passed and echos the parameter after that
# -> the name of the crate
get_crate_name(){
    # While there are still arguments left
    while [[ $# -gt 1 ]]
    do
        if [ "$1" ==  "--crate-name" ];
        then
            echo "$2"
            return
        fi
        shift 1     # shift arguments one to left, i.e. $2 becomes $1 etc.
    done
}

case $(get_crate_name "$@") in
    uhyve|uhyvelib)
        EXTRA_OPTIONS=("-Zinstrument-coverage" "-Clink-dead-code")
        ;;
    *)
        ;;
esac

exec "$@" "${EXTRA_OPTIONS[@]}"