#!/usr/bin/env bash

exit_with_error() {
    echo "Error: $*"
    exit 1
}
# from https://stackoverflow.com/a/246128
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
UHYVE_CODECOV_TOKEN="${UHYVE_CODECOV_TOKEN:-dummytoken}"    # Set dummy token, if no token passed (for grcov)

if ! command -v rustup &>/dev/null; then
    echo "Error: rustup could not be found! Exiting"
    exit 1
fi
# Implicitly assumes that cargo is there if rustup is available
if ! cargo profdata --help &>/dev/null; then
    echo "Warning: cargo profdata not available. Attempting to install via rustup"
    echo "This adds llvm-tools-preview and cargo-binutils."
    # shellcheck disable=SC2015
    rustup component add llvm-tools-preview &&
        cargo install cargo-binutils &&
        cargo profdata --help &>/dev/null ||
        exit_with_error "Error when installing llvm-tools-preview or cargo-binutils"
fi

if ! rustfilt --version &>/dev/null; then
    echo "rustfilt not found. It is required for demangling function names"
    echo "Attempting to install rustfilt via cargo"
    # shellcheck disable=SC2015
    cargo install rustfilt \
    && rustfilt --version &>/dev/null \
    || exit_with_error "Failed to install rustfilt"
fi

if ! grcov --version &>/dev/null; then
    echo "Grcov not found. Attempting to install via cargo"
    # shellcheck disable=SC2015
    cargo install grcov \
    && grcov --version &>/dev/null \
    || exit_with_error "Failed to install grcov"
fi

# Test coverage requires clean build, so that everything is instrumented
cargo clean
echo "Running cargo test. This may take a while."

# Run tests and collect information about the filenames of the executables in json format
# The RUSTC_WRAPPER adds the coverage specific flags to our crate executables (which are not doc tests)
TEST_JSON_OUTPUT="$(
        RUSTDOCFLAGS="-Zinstrument-coverage -Zunstable-options --persist-doctests  target/debug/doctestbins" \
        LLVM_PROFILE_FILE="uhyve-%m.profraw" \
        RUSTC_WRAPPER="$DIR/coverage_rustcwrapper.sh" \
        cargo test --message-format=json
)"
if [ $? != 0 ]; then
    exit_with_error "Coverage run of cargo test failed." "$TEST_JSON_OUTPUT"
fi
echo "Finished cargo test successfully"
cargo profdata -- merge -sparse uhyve-*.profraw -o uhyve.profdata \
    || exit_with_error "Failed to merge raw profiling data"

# Generate code coverage in coveralls JSON format
grcov "$DIR" --source-dir "$DIR" \
    --binary-path "$DIR/target/debug" \
    --output-type coveralls \
    --token "$UHYVE_CODECOV_TOKEN" > coveralls.json \
 || exit_with_error "grcov did not successfully generate a coverage report"

# Todo: make this whole part optional, since we might be only interested in coveralls report
# Remove non JSON parts. Assumes all json lines start with '{' (valid for cargo output as of now)
# but this may break sometime.
FILTERED_TEST_JSON_OUTPUT=$(grep '^[\{]' <<<"$TEST_JSON_OUTPUT")
# Get test executable names (adapted from https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/source-based-code-coverage.html)
JQ_OUTPUT=$(jq -r "select(.profile.test == true) | .filenames[]" <<<"$FILTERED_TEST_JSON_OUTPUT")
JQ_RETURN=$?
TEST_FILES=$(grep -v dSYM - <<<"$JQ_OUTPUT")
GREP_RETURN=$?
if [ $JQ_RETURN != 0 ]; then
    jq_input=$(mktemp)
    jq_output=$(mktemp)
    echo "$FILTERED_TEST_JSON_OUTPUT" >"$jq_input"
    echo "$JQ_OUTPUT" >"$jq_output"
    echo "Error: using jq to parse test executable names from cargo output."
    echo "The input json was dumped to  'file://$jq_input'."
    echo "The Output of jq was dumped  'file://$jq_output'."
    exit 1
fi
if [ $GREP_RETURN != 0 ]; then
    echo "Grep reported an error - dumping output:"
    echo "$TEST_FILES"
    exit 1
fi
echo "Info: Detected the following Test executables: $TEST_FILES"

DOC_TEST_BINS=("$DIR/target/debug/doctestbins/*/rust_out")
# Generate options to pass paths to all test executables to llvm-cov
CARGO_COV_OBJECTS=$( \
    for file in $TEST_FILES $DOC_TEST_BINS; do \
        [[ -x "$file" ]] \
        && printf "%s %s " "-object" "$file" \
        || exit_with_error "Error merging file $file"; \
    done \
)

# Print summary on cmdline
cargo cov -- report \
    --use-color \
    --ignore-filename-regex='/.cargo/registry' \
    --instr-profile=uhyve.profdata \
    $CARGO_COV_OBJECTS