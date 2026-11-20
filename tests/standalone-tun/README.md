# Test: TUN; standalone; nopriv

Run an end-to-end IPv4 TUN test with the standalone HTTP server.

The test uses a rootless user namespace with two private network namespaces.
A veth pair carries the HTTP connection between them, while ICMP traffic is forwarded through the client's and server's real TUN interfaces.
