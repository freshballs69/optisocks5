# optisocks5

A **sans-IO** SOCKS5 codec (C++ core, CPython binding) plus an **optimistic**,
pipelining client. Like pysocks, but the protocol owns no sockets and never
waits between handshake phases — bring your own event loop (blocking, epoll,
asyncio).

## Layout

| Module | What | I/O? |
|---|---|---|
| `optisocks5.core` | the agnostic layer: C++ codec (`client_greeting`, `userpass_auth`, `request`, `parse_reply`, `udp_encapsulate`/`udp_decapsulate`) + the sans-IO `Session` (`optimistic_pipeline()` glues greeting+auth+request; `feed()` consumes replies) | none |
| `optisocks5.sync` | blocking-sockets drivers: `Client` (staged) and `OptimisticClient` (one-shot) | blocking |
| `optisocks5.aio` | asyncio drivers: `AsyncClient` and `AsyncOptimisticClient` | asyncio |

Every public name is also re-exported at the top level (`import optisocks5 as
s5; s5.OptimisticClient`). The C extension itself is `optisocks5._core`.

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

See `examples/async_connect.py` for a full asyncio driver.
