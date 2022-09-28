For the original Cannoli readme, check [here](https://github.com/marginresearch/cannoli).

# Cannonball

Cannonball is a coverage tracer that runs really fast! It uses Cannoli (which it's forked from...we'll work on that) to get coverage information of all branches in
one or more executions of a program and output it as (for now...) JSON. It works on
x86_64 only for now, although there is no reason it won't work on other architectures
once objects and disassembly are taken care of.

## Dependencies

We have a few dependencies!

### Rust

Obviously, you will need the rust toolchain. If you don't have it, you can install
it from [here](https://rustup.rshttps://rustup.rs//).

### QEMU Deps

You will also need the build dependencies for [QEMU](https://github.com/qemu/qemu)
which you can install with:

* Fedora - `sudo dnf build-dep qemu`
* Debian/Ubuntu - `sudo apt-get build-dep qemu`

### Capstone

You also need [capstone](https://github.com/capstone-engine/capstone). If you are on
Debian or Ubuntu, you can install it with `sudo apt-get install libcapstone4-dev`.

If you are on Fedora, you'll need to build from source:

```
git clone https://github.com/capstone-engine/capstone
cd capstone
./make.sh
sudo ./make.sh install
```

## Building

First we need to build cannoli and the jitter library:

```
cargo +nightly build --release
```

Then you can build cannonball:

```
cd cannonball
cargo +nightly build
```

## Running

```
cd cannonball
cargo +nightly run
```

You probably want to pass args though, to do that you'd do something like:

```
cd cannonball
cargo +nightly run -- \
   -i ./tests/inputs/poll_AIS-Lite_0.poll \
   -j ../target/release/libjitter_always.so \
   -l ./tests/libs/ \
   -q ./tests/bundles/qemu/exodus/bin/qemu-x86_64 \
   -t 4 \
   ./tests/bins/AIS-Lite-pie
```