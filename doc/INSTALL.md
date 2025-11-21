# Building httun

## Prerequisites

httun requires
[Rust 1.88](https://www.rust-lang.org/tools/install)
or later to be installed on your system to build the source code.

## Building the source code

To build the source code, you can use the provided build scripts for convenience.
These scripts automate the build process and ensure all necessary dependencies are handled correctly.

Run the `build.sh` script located in the root directory of the project:

```sh
./build.sh
```

This script compiles the entire project using the default settings.

The build script uses
[cargo-auditable](https://crates.io/crates/cargo-auditable)
to create auditable binaries, if `cargo-auditable` is installed.

# Installing httun

## Installing client

To install the client, use the provided `install-client.sh` script.
This script automates the installation process and ensures all necessary components are set up correctly.

Execute the script as follows:

```sh
./install-client.sh
```

## Installing server: FCGI

For installing the FCGI server, use the `install-fcgi.sh` script.
This script configures the httun server to work with web servers like Apache or lighttpd.
This script automates the installation process and ensures all necessary components are set up correctly.

Execute the script as follows:

```sh
./install-fcgi.sh
```

## Installing server: Standalone

To install the httun server in standalone mode (not FCGI), use the `install-standalone.sh` script.
This script sets up the server to run independently without requiring a web server.
This script automates the installation process and ensures all necessary components are set up correctly.

Execute the script as follows:

```sh
./install-standalone.sh
```
