# pycat

A minimal netcat clone built with raw sockets in Python. Constructs IP and TCP packets from scratch, including the three-way handshake, data transfer, and connection teardown.

Requires admin/root privileges to open raw sockets.

## Usage

**Server** (listen for a connection):
```
python raw_server.py [port]
```

**Client** (connect and send data via stdin):
```
python raw_client.py <host> [port]
```

Default port is `9999`.

## Files

- `raw_server.py` — Listens on a port, completes the TCP handshake, and prints received data to stdout.
- `raw_client.py` — Connects to a server, reads lines from stdin, and sends them as TCP segments.
