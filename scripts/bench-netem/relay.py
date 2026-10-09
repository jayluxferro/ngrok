#!/usr/bin/env python3
# Userspace token-bucket relay for the bench's netem variant.
#
# WHY THIS EXISTS: the netem variant needs the carrier constrained to
# ~10 Mbit/s so the dedup byte win can show as wall time. The target
# environment (the bench container VM) cannot shape in the kernel: its
# kernel ships CONFIG_NET_SCH_FQ_CODEL and nothing else -- no htb, no tbf,
# no netem -- its tc binary cannot load modules, and the container holds no
# CAP_NET_ADMIN in its own netns. So the shaper is this userspace relay: it
# owns the address clients dial (127.0.0.1:<tunnel port>) and forwards to
# ngrokd parked on 127.0.0.2 (BENCH_TUNNEL_BIND, see bench.sh). OFF and ON
# legs traverse the same relay, so the leg delta still isolates the codec;
# the absolute numbers are relay-flavored, not tc-flavored, and the reports
# say so.
#
# One GLOBAL bucket counts every relayed byte -- TCP and UDP, both
# directions -- modeling "one 10 Mbit wire", the same shape the tc plan
# would have used (all carrier packets into one htb class). The burst
# (default 64 KiB) is queue depth, not extra bandwidth: sustained throughput
# converges to the rate either way.
#
# Runs inside the throwaway netns netem-run.sh creates; nothing here
# outlives the unshare process, so there is no cleanup to forget.

import argparse
import asyncio
import signal
import sys
import time


class Bucket:
    """Refill-at-rate token bucket; take(n) blocks until n bytes of credit."""

    def __init__(self, rate, burst):
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last = time.monotonic()
        self.relayed = 0

    async def take(self, n):
        while True:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens >= n:
                self.tokens -= n
                self.relayed += n
                return
            await asyncio.sleep(max((n - self.tokens) / self.rate, 0.001))


async def pipe(reader, writer, bucket):
    try:
        while True:
            chunk = await reader.read(16384)
            if not chunk:
                break
            await bucket.take(len(chunk))
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_tcp(reader, writer, bucket, target_host, target_port):
    try:
        treader, twriter = await asyncio.open_connection(target_host, target_port)
    except OSError as exc:
        # Usually "ngrokd not up yet"; the client will see the reset and the
        # harness's own waits will report it coherently.
        print(f"relay: upstream dial failed: {exc}", file=sys.stderr)
        writer.close()
        return
    await asyncio.gather(
        pipe(reader, twriter, bucket),
        pipe(treader, writer, bucket),
    )


class UDPListener(asyncio.DatagramProtocol):
    def __init__(self, relay):
        self.relay = relay

    def connection_made(self, transport):
        self.relay.listener_transport = transport

    def datagram_received(self, data, addr):
        self.relay.up_queue.put_nowait((addr, data))


class UDPUpstream(asyncio.DatagramProtocol):
    # One connected upstream socket per client address -- plain NAT
    # semantics, so the QUIC server's replies find their way back and the
    # client never sees an address change (no migration path to exercise).
    def __init__(self, relay, client_addr):
        self.relay = relay
        self.client_addr = client_addr

    def connection_made(self, transport):
        self.relay.upstreams[self.client_addr] = transport

    def datagram_received(self, data, addr):
        self.relay.down_queue.put_nowait((self.client_addr, data))

    def error_received(self, exc):
        print(f"relay: udp upstream error: {exc}", file=sys.stderr)


class Relay:
    def __init__(self, bucket, target_host, target_port):
        self.bucket = bucket
        self.target_host = target_host
        self.target_port = target_port
        self.up_queue = asyncio.Queue()
        self.down_queue = asyncio.Queue()
        self.upstreams = {}
        self.listener_transport = None

    async def up_worker(self):
        loop = asyncio.get_running_loop()
        while True:
            addr, data = await self.up_queue.get()
            await self.bucket.take(len(data))
            transport = self.upstreams.get(addr)
            if transport is None:
                # create_datagram_endpoint returns after connection_made, so
                # the upstreams map is populated by the time this returns.
                transport, _ = await loop.create_datagram_endpoint(
                    lambda a=addr: UDPUpstream(self, a),
                    remote_addr=(self.target_host, self.target_port),
                )
            transport.sendto(data)

    async def down_worker(self):
        while True:
            client_addr, data = await self.down_queue.get()
            await self.bucket.take(len(data))
            if self.listener_transport is not None:
                self.listener_transport.sendto(data, client_addr)


async def stats(bucket, interval):
    start = time.monotonic()
    while True:
        await asyncio.sleep(interval)
        # The progress line doubles as the shaping evidence: the OFF leg's
        # relayed byte total should land within a burst of its offered
        # bytes, and its wall time should respect rate = bytes/time.
        print(
            "relay: t=%.0fs relayed=%d bytes (rate %.0f B/s)"
            % (time.monotonic() - start, bucket.relayed, bucket.rate),
            file=sys.stderr,
        )


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=15443)
    ap.add_argument("--target", default="127.0.0.2")
    ap.add_argument("--target-port", type=int)
    ap.add_argument("--rate", type=float, default=1250000.0,
                    help="bucket refill, bytes/s (default ~10 Mbit/s)")
    ap.add_argument("--burst", type=float, default=65536.0)
    ap.add_argument("--stats-interval", type=float, default=10.0)
    args = ap.parse_args()
    target_port = args.target_port if args.target_port is not None else args.port

    bucket = Bucket(args.rate, args.burst)
    relay = Relay(bucket, args.target, target_port)

    loop = asyncio.get_running_loop()
    stop = loop.create_future()

    def on_term():
        print(
            "relay: exiting, relayed=%d bytes over %.0fs"
            % (bucket.relayed, time.monotonic() - start),
            file=sys.stderr,
        )
        if not stop.done():
            stop.set_result(None)

    start = time.monotonic()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, on_term)

    tcp = await asyncio.start_server(
        lambda r, w: handle_tcp(r, w, bucket, args.target, target_port),
        args.listen,
        args.port,
    )
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: UDPListener(relay), local_addr=(args.listen, args.port)
    )
    print(
        "relay: tcp+udp %s:%d -> %s:%d at %.0f B/s (burst %d)"
        % (args.listen, args.port, args.target, target_port, args.rate, args.burst),
        file=sys.stderr,
    )
    workers = [
        asyncio.create_task(relay.up_worker()),
        asyncio.create_task(relay.down_worker()),
        asyncio.create_task(stats(bucket, args.stats_interval)),
    ]
    await stop
    tcp.close()
    udp_transport.close()
    for w in workers:
        w.cancel()


if __name__ == "__main__":
    asyncio.run(main())
