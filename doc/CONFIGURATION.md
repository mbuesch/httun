# Configuring httun

httun is configured using TOML configuration files.
The client is configured with `client.conf` and the server with `server.conf`.

By default, the client looks for `/opt/httun/etc/httun/client.conf` and the server for `/opt/httun/etc/httun/server.conf`.
The installation scripts will install example configuration files to these locations.

## Client Configuration (`client.conf`)

The client configuration is mainly composed of one or more `[[channels]]` sections.
Each channel represents a tunnel connection.

### Main client `[[channels]]` fields

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

For a full documentation see the comments with each option from the example configuration file.

## Server Configuration (`server.conf`)

The server configuration also uses `[[channels]]` sections to define the available tunnels.

### Main server `[[channels]]` fields

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

For a full documentation see the comments with each option from the example configuration file.

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
