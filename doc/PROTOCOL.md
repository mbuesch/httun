# httun protocol

The httun protocol has up to four layers:

1. the HTTP frame
2. the encrypted and authenticated httun frame
3. (in case of L7 mode) the L7 container frame
4. user frames. Either L3 (IP) or L7 (socket)

These layers wrap each other from (1) to (4).
Where (1) is the outer frame visible to the public network.

## L3 mode (TUN)

In L3 mode
1. user frames are wrapped in encrypted httun frames
2. which are wrapped in standard HTTP frames (GET or POST)
3. which are transmitted over the network.

## L7 mode (socket)

In L7 mode
1. user frames are wrapped in L7 container frames
2. which are wrapped in encrypted httun frames
3. which are wrapped in standard HTTP frames (GET or POST)
4. which are transmitted over the network.

## HTTP frame

The HTTP layer frame is supposed to look as normal as possible, to pass through as much HTTP processing as possible.

It is a standard HTTP request or response.
There are no httun-specific extensions to the HTTP protocol.

Only HTTP GET and POST requests are used.

### GET requests

When requesting data from the server (data direction server -> client), then HTTP GET requests are used.

These GET requests still carry a small httun frame, though.
As HTTP GET requests typically don't have a body part, this httun frame is encoded in the URL as a query parameter.

The attached httun frame is put into the query parameter with the name `m`.
The encrypted httun frame is base64 encoded in the `m` query parameter's value.

### POST requests

When sending data to the server (data direction client -> server), then HTTP POST requests are used.
The httun frame is put into the body of the POST request as `content-type: application/octet-stream`.

TODO

## httun frame

The httun frame is encrypted and authenticated using AES-256-GCM.
The encryption key is a pre-shared 32-byte key.

The frame is composed of four areas:
- `assoc`: Authenticated, but not encrypted associated data.
- `nonce`: A unique number for each message to initialize the cipher.
- `crypt`: The encrypted and authenticated data.
- `tag`: The authentication tag, which ensures the integrity of the `assoc` and `crypt` data.

### httun Frame Layout

| Byte offs | Name        | Byte size | Area  | Description                                |
|-----------|-------------|-----------|-------|--------------------------------------------|
| 0         | Type        | 1         | assoc | Basic message type.                        |
| 1         | Nonce       | 16        | nonce | A randomly generated nonce for encryption. |
| 17        | Operation   | 1         | crypt | The operation this message performs.       |
| 18        | Seq counter | 8 (be)    | crypt | A sequence number.                         |
| 26        | Payload len | 2 (be)    | crypt | Length of the following payload in bytes.  |
| 28        | Payload     | var       | crypt | Payload data.                              |
| var       | Auth tag    | 16        | tag   | AES-GCM authentication tag.                |

#### httun Frame Element: Type

This 1-byte field is not encrypted, but is authenticated.

| Value | Name | Description                  |
|-------|------|------------------------------|
| 0     | Init | An initialization message.   |
| 1     | Data | A regular data message.      |

#### httun Frame Element: Nonce

The nonce is a cryptographically randomly generated number.

#### httun Frame Element: Operation

A 1-byte field that defines the type of the payload.

| Value | Name         | Description                     |
|-------|--------------|---------------------------------|
| 0     | `Init`       | Initialization.                 |
| 1     | `L3ToSrv`    | Layer 3 packet to the server.   |
| 2     | `L3FromSrv`  | Layer 3 packet from the server. |
| 3     | `L7ToSrv`    | Layer 7 data to the server.     |
| 4     | `L7FromSrv`  | Layer 7 data from the server.   |
| 5     | `TestToSrv`  | Test message to the server.     |
| 6     | `TestFromSrv`| Test message from the server.   |

#### httun Frame Element: Seq counter

TODO

#### httun Frame Element: Payload len

TODO

#### httun Frame Element: Payload

TODO

#### httun Frame Element: Auth tag

TODO

## L7 container frame

When the httun frame's `Operation` is `L7ToSrv` or `L7FromSrv`, the payload of the httun frame is an L7 container.
This container holds the destination address and port for the user data.

### L7 Container Layout

| Byte offs | Name                 | Byte size | Description                     |
|-----------|----------------------|-----------|---------------------------------|
| 0         | Destination Address  | 16        | The destination IPv4/6 address. |
| 16        | Destination Port     | 2 (be)    | The destination port number.    |
| 18        | Payload              | var       | The actual L7 user data.        |

This structure allows httun to forward generic TCP/UDP-like traffic to a specific destination on the other side of the tunnel.

#### L7 Frame Element: Destination Address

The destination address is an IPv6 address or an IPv4-mapped IPv6 address.

#### L7 Frame Element: Destination Port

The destination port number is a 16-bit unsigned integer in big-endian format.

#### L7 Frame Element: Payload

The payload contains the actual L7 (socket) user data that is to be forwarded to the destination address and port.
