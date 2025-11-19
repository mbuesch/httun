# Encrypted HTTP tunnel for IP4/6 or layer-7 network traffic

httun is a network tunneling tool for tunneling arbitrary network traffic over HTTP(s).

The tunnel is always strongly encrypted and authenticated.

## Why?

Some public "internet" access points only allow access to certain ports and protocols.

HTTP almost certainly is one of the allowed protocols.

If you only have access to one of these limited access points you can use your httun server to tunnel to the real internet with all services available that you enable in your server routing/firewall.

## What kind of traffic can be tunneled?

1. IP v4 and IP v6 traffic can be tunneled.
   In this case the endpoints are Linux TUN endpoints on both the client machine and the server machine.
   Normal Linux configuration, routing and filtering tools are used to integrate the TUN endpoints into your network structure.
2. Simple socket traffic (ISO/OSI layer 7) can be also tunneled.
   In this case a local socket is opened by the client software.
   It listens on one given port locally for incoming traffic.
   This traffic and a target machine address/port tuple is then tunneled to the server machine where a socket is opened to the target machine.

The tunnelling option 1. is preferred, because it's much more flexible.
But it's also much harder to set up due to the need to configure and route the traffic to and from the Linux TUN endpoints.
Standard Linux routing (ip route) and filtering (nftables / iptables) can be used.

The tunnelling option 2. has the downside that it is restricted to a single port and that it basically pokes a hole through your server firewall.
Therefore, use it with care.
httun provides some server side block- and allow-list based filtering to mitigate this risk.
But it has the advantage that it's easier to set up.

This powerful tool comes with great benefits if used correctly and it comes with risks if used incorrectly.
Like with any other tunnelling/VPN tool.
Please read the httun documentation to understand both the potential and the risk of httun tunnelling.

## Maturity

This project is not stable, yet.
Breaking protocol and API changes can happen at any time.

This project is usable in its current state, but it is work in progress.
I try to keep breakages minimal, but I currently can't guarantee long-term stability, yet.

## Security

Strong AES-GCM AEAD encryption and authentication is always used for all packets sent over the tunnel.
The use of HTTPs is not required for secure communication.
The protocol is completely decoupled from HTTP(s) and it merely uses HTTP(s) as a dumb transport layer.

Currently only symmetric encryption is supported.
That means the client and the server machine share a common secret.
This is known to be not ideal and future plans include the introduction of some kind of asymmetric key handling in addition to the symmetric key handling.

## Performance

The performance overhead of tunnelling traffic over HTTP is big, of course.
HTTP is a verbose protocol with large headers.
httun tries to minimize the header sizes where possible, but of course it can't control them all.

However, the performance of httun is still pretty good.

It highly depends on what your application traffic looks like.
If the application sends mainly only small packets, then this will result in a rather large overhead.
But if the application can send large packages then the overhead of the HTTP headers and the httun headers is quite small compared to the application payload.

Throughput of more than 10 MBit/s is possible.
But it depends on your application what throughput you can actually get.

Latency is also much increased, as compared to direct network connections.
Expect a latency overhead of at least 10 ms.

## The server - Either FCGI or Standalone

The server can be run

1. as FCGI server together with Apache, lighttpd or any other HTTP web server which supports the FCGI protocol.
2. as a very simple standalone HTTP server that does not require other real web server software to be run on the server side.

This gives you the full flexibility to either

1. plug httun into your existing Apache/lighttpd/etc infrastructure and serve a httun tunnel from an arbitrary URL path of your existing setup or
2. run httun standalone with no web server overhead.

# Building

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

# Installing

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

# Configuring

httun is configured using TOML configuration files.
The client is configured with `client.conf` and the server with `server.conf`.

By default, the client looks for `/opt/httun/etc/httun/client.conf` and the server for `/opt/httun/etc/httun/server.conf`.
The installation scripts will install example configuration files to these locations.

## Client Configuration (`client.conf`)

The client configuration is mainly composed of one or more `[[channels]]` sections.
Each channel represents a tunnel connection.

### Client `[[channels]]` fields

- `urls`:
   A list of URLs for the httun server endpoint.
   All of these server endpoints will match this `[[channels]]` entry.
- `name`:
   The name of the channel.
   This should match a channel name on the server.
   The default is "a".
- `shared-secret`:
   The pre-shared key for encryption and authentication.
   This must be the same on both the client and the server for a given channel.
- `http-basic-auth`:
   If the server requires HTTP Basic Authentication, you can configure the username and password here.
- `https-ignore-tls-errors`:
   If you are using HTTPS with a self-signed certificate, you can set this to `true` to ignore TLS errors.
   This does not affect the security of the httun tunnel itself, as it uses its own end-to-end encryption.

## Server Configuration (`server.conf`)

The server configuration also uses `[[channels]]` sections to define the available tunnels.

### Key `server.conf` options:

- `name`:
   The name of the channel.
   This should match the name configured on the client.
   The default is "a".
- `shared-secret`:
   The pre-shared key for encryption and authentication.
   This must be the same on both the client and the server for a given channel.
- `tun`:
   The name of the Linux TUN device to create for this channel (e.g., "httun-s-a").
   If this option is omitted, Layer 3 (IP) tunneling is disabled for this channel.
- `enable-test`:
   Allows the client to run a connection test using `httun-client test`.
- `l7-tunnel`: This section configures Layer 7 (socket) tunneling.
   - `disabled`: Set to `false` to enable L7 tunneling.
   - `bind-to-interface`: (Optional) Bind outgoing L7 tunnel connections to a specific network interface.
   - `address-denylist` and `address-allowlist`: These lists control which destination IP addresses are allowed for L7 tunnels. It is highly recommended to configure these to restrict access and enhance security. The allowlist has precedence over the denylist.

### Generating a Shared Secret

It is strongly recommended to generate a new, random shared secret for each channel.
Re-using the same secret for different channels does compromise security.
You can do this with the following command:

```sh
httun-client genkey
```

This will output a new key that you can copy into your `client.conf` and `server.conf`.

## Example: Linux TUN based tunnel

TODO

## Example: ISO/OSI layer 7 (socket) tunnel

TODO

# Distribution packaging

TODO

# License

Copyright (c) 2025 Michael Büsch <m@bues.ch>

Licensed under the Apache License version 2.0 or the MIT license, at your option.
