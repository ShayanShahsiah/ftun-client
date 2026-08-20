# ftun-client

A domain-fronting TCP tunnel client. It listens on a local TCP port and relays each
connection to a hidden origin server through a CDN, disguising the traffic as an ordinary
HTTPS request to an innocuous, unrelated domain.

To a passive network observer, the connection looks like plain HTTPS to a popular website
(e.g. `www.python.org`). The real destination is carried inside the encrypted HTTP/2
`:authority` header and only revealed to the CDN after TLS termination.

## How it works

The client uses **domain fronting** over HTTP/2:

1. A local application connects to the client's bind address (default `127.0.0.1:9080`).
2. The client opens a TLS connection to a **front domain** on port 443, with the TLS SNI
   set to that front domain and ALPN negotiated to `h2`.
3. Over that connection it sends HTTP/2 requests whose `:authority` header points at the
   **real origin** (`meek.ramennoodles.net.global.prod.fastly.net`, a Fastly backend),
   not the front. The CDN routes on the inner header, so the traffic reaches the origin
   while the visible SNI stays innocuous.
4. Two streams carry the tunnel, tied together server-side by a shared `x-session-id` (UUID):
   - **Stream 1 (`GET`)** — downstream data (origin → client), delivered as the response body.
   - **Stream 3 (`POST`)** — upstream data (client → origin), streamed as the request body.
5. The client relays bytes between the local socket and the two HTTP/2 streams with a
   non-blocking `select()` loop, applying HTTP/2 flow control and honoring EOF in both
   directions.

Each accepted connection is handled on its own `ClientThread`. Requests are authenticated
with a shared token sent in the `x-ramen-auth` header.

> This is the client half of the tunnel. It expects a matching server deployed as the
> Fastly origin referenced by `ORIGIN` in `consts.py`.

## Requirements

- Python 3.10+ (uses structural pattern matching)
- Dependencies from `requirements.txt`:
  - `certifi`
  - `dnspython`
  - `h2`

## Installation

```sh
git clone https://github.com/ShayanShahsiah/ftun-client.git
cd ftun-client
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Configuration

- **`auth.txt`** — the shared authentication token, read from the first line and sent in
  the `x-ramen-auth` header. It must match the value the server expects.
- **`fronts.txt`** — a newline-separated list of front domains used in randomize mode.
  These must be domains served by the same CDN as the origin for fronting to work. The
  file is re-read on every incoming connection, so it can be edited without restarting.
- **`consts.py`** — origin hostname, default bind IP/port, default front, buffer sizes,
  and timeouts.

## Usage

Run directly:

```sh
.venv/bin/python client.py [options]
```

Or via the helper script (which invokes `.venv/bin/python client.py`):

```sh
./run.sh [options]
```

### Options

| Flag | Argument | Description |
| --- | --- | --- |
| `-b`, `--bind` | `<IP>[:PORT]` | Local listen address. Default `127.0.0.1:9080`. Give `:PORT` alone to bind `0.0.0.0:PORT`. |
| `-f`, `--front` | `<HOST>[:PORT][:RESOLVE_IP]` | Front domain (default `www.python.org:443`). Supply `RESOLVE_IP` to skip DNS and connect straight to that IP. |
| `-r`, `--randomize` | — | Pick a random front from `fronts.txt` for each connection (ignores `-f`). |
| `-info` | — | Log at `INFO` level (default is the more verbose `DEBUG`). |

### Examples

Listen on the default `127.0.0.1:9080`, fronting through `www.python.org`:

```sh
./run.sh
```

Listen on port 8080 and front through a specific domain:

```sh
./run.sh -b :8080 -f www.wikihow.com
```

Pin the front's IP to skip DNS resolution:

```sh
./run.sh -f www.python.org:443:151.101.0.223
```

Rotate through a random front per connection with quieter logging:

```sh
./run.sh -r -info
```

Point a local application at the client's bind address as if it were a plain TCP endpoint,
and its traffic is tunneled to the origin.

## Notes

- Domain fronting relies on the CDN routing by inner `:authority` rather than SNI; whether
  a given front works depends on the CDN's current behavior, and providers may change this.
- The TLS handshake advertises a browser-like cipher list and a Firefox `User-Agent` to
  blend in with ordinary traffic.
- The client shuts down cleanly on `SIGINT` (Ctrl-C, exit 130) and `SIGTERM` (exit 143),
  joining active threads before closing. Windows is supported via a stdin-EOF shutdown path.
- Treat the token in `auth.txt` as a secret — rotate it if the repository is public.
