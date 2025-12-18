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
There are no httun specific extensions to the HTTP protocol.

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

TODO

## L7 container frame

TODO
