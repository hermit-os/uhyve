#!/usr/bin/env bash

if [ "$1" = "--help" ]; then
  cat 1>&2 <<EOF
USAGE: build_data_images.sh

NOTE: In order to determine the hermit version, this program requires that either
the environment variable HERMIT_MANIFEST_DIR is set, or that \`cargo metadata\` + \`jq\`
can be used to find the default HERMIT_MANIFEST_DIR as the one used by \`tests/test-kernels\`.

Dependencies:
* bash
* cargo metadata
* jq
EOF
  exit
fi

set -e

# The architecture subdirectory name
arch="$(uname -m)"

cd "$(dirname "$0")/.."

echo "Repository directory: $(pwd)"

if [ -z "$HERMIT_MANIFEST_DIR" ]; then
  hermit_rs_lib_rs="$(cargo metadata -m tests/test-kernels/Cargo.toml --format-version 1 | jq -r '.packages | map(select(.name == "hermit"))[0].targets | map(select(.name == "hermit"))[0].src_path')"
  hermit_rs="$(realpath "$(dirname "$hermit_rs_lib_rs")/..")" # "

  echo "hermit-rs directory: $hermit_rs"

  export HERMIT_MANIFEST_DIR="$(dirname "$hermit_rs")/kernel"
fi

echo "HERMIT_MANIFEST_DIR: $HERMIT_MANIFEST_DIR"

# The hermit kernel version
hermit_kv="$(cargo metadata -m "$HERMIT_MANIFEST_DIR/Cargo.toml" --format-version 1 | jq -r '.workspace_members | map(select(contains("hermit-kernel@")) | split("@")[1])[0]')"

echo "hermit-kernel version: $hermit_kv"

# TODO
exit 1

mkdir -p "data/$hermit_kv/$arch"
cd "data/$hermit_kv/$arch"
