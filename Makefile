.PHONY: check coverage fuzz fuzz-loop fuzz-seeds
.DEFAULT_GOAL := check

# The fuzz budget per target in seconds, the jobs to run it on and the
# sanitizer to build with. The sanitizer stays off by default, its runtime
# hangs before main on macOS.
FUZZ_TIME ?= 180
FUZZ_JOBS ?= $(shell nproc 2>/dev/null || sysctl -n hw.ncpu)
FUZZ_SANITIZER ?= none

# check runs the gates CI holds a push to, the formatting, clippy, the docs and
# the tests of every feature combination.
check:
	cargo fmt --all -- --check
	cargo clippy --all-features -- -D warnings
	cargo doc --all-features --no-deps
	cargo hack test --each-feature
	cargo test --all-features

# coverage measures the test coverage of the library code and opens the HTML
# report. It needs nightly to leave the test modules out of the numbers. The
# previous instrumented build is dropped first, as a test binary left behind
# by another toolchain would get merged into the report as uncovered code.
coverage:
	rm -rf target/llvm-cov-target
	cargo +nightly llvm-cov --html --open

# fuzz-seeds regenerates the fuzz seed corpora from the scenario tests, every
# script they run written out as the fuzzers read it. The fuzzers start from
# these alongside their own corpus. Each mock names the target it seeds, so a
# target left without seeds means the name drifted from the binary.
fuzz-seeds:
	rm -rf fuzz/seeds
	WIRE_SEEDS=$(CURDIR)/fuzz/seeds cargo test --features fuzz --quiet
	for target in $$(cargo +nightly fuzz list); do \
		test -d fuzz/seeds/$$target || { echo "no seeds for $$target"; exit 1; }; \
	done

# fuzz runs every fuzz target for the budget each on all cores, from its corpus
# and the seeds, stopping at the first finding.
fuzz:
	for target in $$(cargo +nightly fuzz list); do \
		cargo +nightly fuzz run -s $(FUZZ_SANITIZER) -j $(FUZZ_JOBS) $$target fuzz/corpus/$$target fuzz/seeds/$$target -- -max_total_time=$(FUZZ_TIME) || exit 1; \
	done

# fuzz-loop runs the fuzz targets round robin until a finding stops it or the
# loop is interrupted, the corpus growing across rounds.
fuzz-loop:
	while true; do $(MAKE) --no-print-directory fuzz || exit 1; done
