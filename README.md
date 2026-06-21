# optisocks5

A **sans-IO** SOCKS5 codec (C++ core, CPython binding) plus an **optimistic**,
pipelining client. Like pysocks, but the protocol owns no sockets and never
waits between handshake phases — bring your own event loop (blocking, epoll,
asyncio).

## Layout

| Module | What | I/O? |
|---|---|---|
| `optisocks5.core` | the agnostic layer: C++ codec — client side (`client_greeting`, `parse_method_selection`, `userpass_auth`, `parse_auth_reply`, `request`, `parse_reply`), server side (`parse_greeting`, `method_selection`, `parse_userpass`, `auth_reply`, `parse_request`, `reply`), `udp_encapsulate`/`udp_decapsulate` — plus the sans-IO `Session` (`optimistic_pipeline()` glues greeting+auth+request; `feed()` consumes replies) and `reply_size()` | none |
| `optisocks5.sync` | blocking-sockets clients: `Client` (staged) and `OptimisticClient` (one-shot) | blocking |
| `optisocks5.aio` | asyncio clients: `AsyncClient` and `AsyncOptimisticClient` | asyncio |
| `optisocks5.server` | hook-driven server: sans-IO `ServerSession` (emits `Send`/`NeedData`/`Authorize`/`Connect`/`Relay`/`Close` intents) + threaded `Server` and asyncio `AsyncServer` | per driver |

Every public name is also re-exported at the top level (`import optisocks5 as
s5; s5.OptimisticClient`, `s5.Server`). The C extension itself is
`optisocks5._core` (shipped with a `_core.pyi` stub; the package is typed).

`Client` vs `OptimisticClient` differ by one feature: the optimistic one ships
the whole handshake in a single send and never waits between phases; the staged
one waits for each phase's reply (and offers multiple auth methods).

**Optimistic** = commit to a single auth method up front (so the server's choice
is predictable) and ship the whole handshake in one `send` instead of paying an
RTT per phase. A byte-exact proxy survives it; a `recv()`-per-phase proxy
desyncs — the read-discipline fingerprint this toolkit studies.

## Build & test

```bash
uv sync --extra dev      # builds the C++ extension + installs pytest
uv run pytest -q
```

## Use

Blocking client:

```python
from optisocks5.sync import OptimisticClient

with OptimisticClient("127.0.0.1", 1080, "user", "pass") as c:
    reply = c.connect("example.com", 443)   # one-shot greeting+auth+CONNECT
    print(reply.ok, c.bound)                 # then c.sock is the live tunnel
```

asyncio client (same Session under the hood):

```python
from optisocks5.aio import AsyncOptimisticClient

async with AsyncOptimisticClient("127.0.0.1", 1080, "user", "pass") as c:
    reply = await c.connect("example.com", 443)
    # c.reader / c.writer are the live tunnel
```

Or drive the sans-IO `Session` yourself in any loop:

```python
from optisocks5.core import Session

sess = Session("user", "pass")
writer.write(sess.optimistic_pipeline("example.com", 443))   # one send
reply = None
while reply is None:
    reply = sess.feed(await reader.read(4096))
```

UDP datagrams (no-handshake relays):

```python
dg = s5.udp_encapsulate("8.8.8.8", 53, query)     # [RSV][FRAG][ATYP][ADDR][PORT][DATA]
frag, host, port, data = s5.udp_decapsulate(reply)
```

Hook-driven server (threaded or asyncio, same `ServerSession` core):

```python
from optisocks5.server import Server

server = Server()                 # an authorize hook flips on userpass auth

@server.authorize                 # s.ok(ctx) / s.reject()
def authorize(s, user, password): s.ok({"user": user})

@server.on_connect                # block / redirect / intercept per request
def on_connect(s, host, port):
    if blocked(host): s.reject()                  # -> error reply
    # s.set_target(h, p)  redirect   |   s.intercept(fn)  serve in-memory
    # s.pipe(fn)          meter/transform the relayed bytes

server.serve("0.0.0.0", 1080)
```

`AsyncServer` is the asyncio mirror (hooks may be `async`). Only CONNECT is
served by default; non-SOCKS5 / bad-ATYP / oversize peers are rejected with a
protocol reply, not left hanging.

See `examples/` — `async_connect.py` (asyncio client), `async_server.py`
(in-memory upstream), `server_metered.py` (per-user byte metering),
`proxy_test.py` (behaviour battery), `selector_connect.py` (selectors fan-out).
