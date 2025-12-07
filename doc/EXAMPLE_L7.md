# Example: ISO/OSI Layer 7 (socket) tunnel

This example demonstrates how to configure a Layer 7 (socket) tunnel.
This allows you to forward TCP-based connections, such as SSH, RDP, or any other TCP service, through the HTTP tunnel.

Let's assume you are behind a restrictive firewall (e.g. at a hotel or in a corporate network) that only allows outbound HTTP traffic.
You want to connect to an SSH server on the internet, but the firewall blocks the SSH port.

You can use httun to bypass this restriction by tunneling the SSH connection over HTTP.
In this scenario, your `httun-server` is running on a publicly accessible machine, and your target SSH server is also on the internet at a known IP address.

## Generate a common secret

First, generate a strong shared secret for the channel:

```sh
httun-client genkey
```

You will get a long random hexadecimal string.
This hexadecimal string is your **secret key** that encrypts your traffic.
Keep it private at all times.

You will use it in both the server and client configuration files.

## Server Configuration (`server.conf`)

On the server, define a channel with a channel `name`, specify the `shared-secret` key and enable the `l7-tunnel`.

```toml
[[channels]]
name = "myL7"
shared-secret = "YOUR_GENERATED_SECRET_KEY_HERE"

# For security, it is highly recommended to configure a denylist and allowlist.
# See the default configuration file for extended denylist/allowlist examples.
l7-tunnel.address-denylist = [
    # Deny all possible connections.
    "0.0.0.0/0",
    "::/0",
]
# Then, explicitly allow connections only to the target SSH server.
# In this example, our target SSH server has the IP 123.123.123.123.
l7-tunnel.address-allowlist = [
    "123.123.123.123",
]
```

This configuration acts as a security measure.
It ensures that your `httun-server` will only ever connect to the specified SSH server IP address and nothing else.

Alternatively, if you trust all your httun users, you may use a less restrictive configuration and allow connections to any IP address, inluding or excluding localhost and the local network.
See the default `server.conf` configuration file for more examples.

## Client Configuration (`client.conf`)

On the client, configure a corresponding channel `name` that points to your `httun-server`'s `url`.

```toml
[[channels]]
urls = [ "http://your-httun-server.example.com/httun" ]
name = "myL7"
shared-secret = "YOUR_GENERATED_SECRET_KEY_HERE"
```

## Running the server

After (re-)starting the server's systemd unit, it will be ready to accept L7 tunneling connections.

```sh
# Run as root:
systemctl restart httun-server.service
```

No network interface configuration is needed on the server for L7 tunneling.

## Running the client

To start the L7 tunnel on the client, use the `socket` subcommand. You need to specify:
1.  The local port the client should listen on (`2222` in this example).
2.  The remote destination host that the `httun-server` should connect to (`123.123.123.123`).
3.  The remote destination port (`22`).

```sh
httun-client 'http://your-httun-server.example.com/httun' socket --local-port 2222 123.123.123.123:22
```

The client will now listen on `127.0.0.1:2222` for incoming connections.

## Using the socket tunnel

You can now connect to your target SSH server by connecting your SSH client to the local port on your client machine.

```sh
ssh user@127.0.0.1 -p 2222
```

Any TCP connection made to `127.0.0.1:2222` on the client will be forwarded through the HTTP tunnel to `123.123.123.123:22` via your `httun-server`.
