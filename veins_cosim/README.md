# Go QUIC-FEC + Veins co-simulation

This is an isolated integration project. It does not replace the existing
`python/bandit`, `go/cmd/quicfec-*`, or Veins example logic.

## Model boundary

The Go endpoints use the repository's real `quic-go` / `fecquic` implementation:
QUIC handshake and TLS, streams and QUIC datagrams, BBRv2, RaptorQ encoding and
decoding, receiver feedback, and ARQ all execute in separate Go processes. An
additive `net.PacketConn` injection point selects the new adapter only for the
`quicfec-veins-*` commands; existing clients and servers still default to their
original UDP `DialAddr` / `ListenAddr` behavior.

The adapter transports each complete QUIC UDP datagram to the corresponding
Veins application over loopback IPC. Veins accounts for IPv4+UDP overhead and
transmits it as a unicast 802.11p WSM through the modeled MAC and PHY. The RSU
maps the QUIC peer's virtual vehicle address back to that vehicle's MAC address.
OMNeT++'s real-time scheduler keeps the Go processes' wall-clock timers aligned
with simulated time. This is a UDP-datagram boundary integration, not a Linux
TAP/netns simulation: Linux kernel IP/UDP behavior is not modeled.

## Period-12, 100-KiB run

- SUMO creates 25 vehicles at 12-second intervals over 300 simulated seconds.
- Each vehicle sends its own 102,400-byte file once to the RSU.
- QUIC-FEC uses K=26, N=32, L=1200 bytes, six initial repairs, ARQ window 8,
  four repairs per NACK, at most five attempts, and BBRv2.
- The inherited Veins background beacons run every 20 ms. PHY bitrate remains
  12 Mbps; the independent scenario places the RSU on the route near the flow
  insertion point so the upload has a decodable radio link. Existing Veins
  experiment files are unchanged.

Build and run from this directory:

```bash
./build.sh
./config/run_period12.sh
```

`run_period12.sh` sources `/opt/omnetpp-6.1/setenv` and the Veins environment,
starts `veins_launchd`, then runs OMNeT++/SUMO in real time. The result directory
is `results/period12_100KiB/`; it contains per-client/server logs, the received
files, OMNeT++ scalars (`channelBusy:timeavg`), and `summary.json` with file
integrity and CBR aggregates. The shorter `[Config Smoke]` is the 20-second
end-to-end check used during integration.
