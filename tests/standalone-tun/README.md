# Test: TUN; standalone; isolated

Run an end-to-end IPv4 TUN test with the standalone HTTP server.

The test prefers a rootless user namespace with two private network namespaces.
If the caller is root, it uses private network namespaces directly.
A veth pair carries the HTTP connection between the namespaces, while ICMP traffic is forwarded through the client's and server's real TUN interfaces.
A non-root run is skipped when the host does not permit unprivileged user namespaces.

This test requires Linux network namespaces, `nsenter`, `unshare`, `ip`,
`ping`, and access to `/dev/net/tun`.
