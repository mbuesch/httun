# Encrypted HTTP tunnel for IP4/6 or layer-7 network traffic

httun is a network tunneling tool for tunneling arbitrary network traffic over HTTP(s).

The tunnel is always strongly encrypted and authenticated.

## Why?

Some public "internet" access points only allow access to certain ports and protocols.

HTTP almost certainly is one of the allowed protocols.

If you only have access to one of these limited access points you can use your httun server to tunnel to the real internet with all services available that you enable in your server routing/firewall.

## What kind of traffic can be tunnelled?

1. IP v4 and IP v6 traffic can be tunneled.
   In this case the endpoints are Linux TUN endpoints on both the client machine and the server machine.
   Normal Linux configuration, routing and filtering tools are used to integrate the TUN endpoints into your network structure.
2. Simple socket traffic (ISO/OSI layer 7) can be also tunnelled.
   In this case a local socket is opened by the client software.
   It listens on one given port locally for incoming traffic.
   This traffic and a target machine address/port tuple is then tunnelled to the server machine where a socket is opened to the target machine.

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

This project is usable as-is, but it is work in progress.
I try to keep breakages minimal, but I currently can't guarantee longterm stability, yet.

## Security

Strong AES-GCM AEAD encryption and authentication is always used for all packets sent over the tunnel.
The use of HTTPs is not required for secure communication.
The protocol is completely decoupled from HTTP(s) and it merely uses HTTP(s) as a dumb transport layer.

Currently only symmetric encryption is supported.
That means the client and the server machine share a common secret.
This is known to be not ideal and future plans include the introduction of some kind of asymmetic key handling in addition to the symmetric key handling.

## Performance

The performance overhead of tunnelling traffic over HTTP is big, of course.
HTTP is a verbose protocol with large headers.
httun tries to minimize the header sizes where possible, but of course it can't control them all.

However, the performance of httun is still pretty good.

It highly depends on what your application traffic looks like.
If the application sends mainly only small packets, then this will result in a rather large overhead.
But if the application can send big packages then the overhead of the HTTP headers and the httun headers is quite small compared to the application payload.

Throughput of more than 10 MBit/s is possible.
But it depends on your application what throughput you can actually get.

Latency is also much elevated, as compared to direct network connections.
Expect a latency overhead of at least 10 ms.

## The server - Either FCGI or Standalone

The server can be run

1. as FCGI server together with Apache, lighttpd or any other HTTP web-server which supports the FCGI protocol.
2. as a very simple standalone HTTP server that does not require other real web-server software to be run on the server side.

This gives you the full flexibility to either

1. plug httun into your existing Apache/lighttpd/etc infrastructure and serve a httun tunnel from an arbitrary URL path of your existing setup or
2. run httun standalone with no web-server overhead.

# Building

## Prerequisites

httun requires
[Rust 1.88](https://www.rust-lang.org/tools/install)
or later to be installed on your system to build the source code.

## Building the source code

TODO

# Installing

## Installing client

TODO

## Installing server: FCGI

TODO

## Installing server: Standalone

TODO

# Configuring

TODO

## Example: Linux TUN based tunnel

TODO

## Example: ISO/OSI layer 7 (socket) tunnel

TODO

# Distribution packaging

TODO

# License

Copyright (c) 2025 Michael Büsch <m@bues.ch>

Licensed under the Apache License version 2.0 or the MIT license, at your option.
