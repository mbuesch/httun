## Example: Linux TUN based tunnel

This example demonstrates how to configure a Layer 3 (IP) tunnel.
This allows you to route IP traffic between the client and the server.

First, generate a strong shared secret for the channel:

```sh
httun-client genkey
```

You will get a long random hexadecimal string.
This hexadecimal string is your **secret key** that encrypts your traffic.
Keep it private at all times.

You will use it in both the server and client configuration files.

### Server Configuration (`server.conf`)

On the server, define a channel with a channel `name` and specify the `shared-secret` key and a `tun` device name to create.

```toml
[[channels]]
name = "mytun"
shared-secret = "YOUR_GENERATED_SECRET_KEY_HERE"
tun = "httun-s-mytun"
enable-test = true
```

Set the `enable-test` option to `true` for initial setup and testing.
This option enables the possibility to do a basic connection test to this server.
You may later set this option to `false` after you verified that your setup works properly.

### Client Configuration (`client.conf`)

On the client, configure a corresponding channel `name` that points to your server's `url`.

```toml
[[channels]]
urls = [ "http://your-server.example.com/httun" ]
name = "mytun"
shared-secret = "YOUR_GENERATED_SECRET_KEY_HERE"
```

### Running the server

After (re-)starting the server's systemd unit, it will create a `httun-s-mytun` network interface.

```sh
# Run as root:
systemctl restart httun-server.service
```

You need to configure this interface with an IP address and bring the TUN interface up.

```sh
# Run as root:
ip addr add 10.1.1.1/24 dev httun-s-mytun
ip link set httun-s-mytun up
```

### Running the client

The client's TUN interface will be configured automatically.
The name of the client's TUN interface will default to `httun-c-0`.
But a different name can be specified on the command line.
See the command line help for more information:

```sh
httun-client --help
httun-client tun --help
```

Bring up the tunnel on the client side by starting the httun client:

```sh
# Run as root:
httun-client 'http://your-server.example.com/httun' tun
```

Assign an IP address to the client TUN interface:

```sh
# Run as root:
ip addr add 10.1.1.2/24 dev httun-c-0
```

You can now test the tunnel by pinging the server from the client:

```sh
ping 10.1.1.1
```
