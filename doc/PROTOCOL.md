# httun protocol

The httun protocol has up to four layers:

1. the HTTP frame
2. the encrypted httun frame
3. (optional) the L7 container frame
4. user frames. Either L3 (IP) or L7 (socket)

These layers wrap each other from (1) to (4).
Where (1) is the outer frame.

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

TODO

## httun frame

TODO

## L7 container frame

TODO
