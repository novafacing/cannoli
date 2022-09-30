For the original Cannoli readme, check [here](https://github.com/marginresearch/cannoli).

# Cantrace

Cantrace is a coverage tracer that runs really fast! It uses Cannoli (which it's forked from...we'll work on that) to get coverage information of all branches in
one or more executions of a program and output it as (for now...) JSON. It works on
x86_64 only for now, although there is no reason it won't work on other architectures
once objects and disassembly are taken care of.

## Building

First we need to build cannoli and the jitter library:

```
cargo +nightly build --release
```

Then you can build cantrace:

```
cd cantrace
cargo +nightly build
```

## Running

```
cd cantrace
cargo +nightly run
```

You probably want to pass args though, to do that you'd do something like:

```
cd cantrace
cargo +nightly run -- \
   -i ./tests/inputs/poll_AIS-Lite_0.poll \
   -j ../target/release/libjitter_always.so \
   -l ./tests/libs/ \
   -q ./tests/bundles/qemu/exodus/bin/qemu-x86_64 \
   -t 4 \
   ./tests/bins/AIS-Lite-pie
```