quicfec-grpc-server

This is a skeleton gRPC control-plane server exposing an Env service to:
- Configure tc netem conditions via Linux tc/ifb
- Reset and run RL-style rollouts (to be wired to QUIC+FEC code)

Build:
- Go modules already configured. Generate protobuf stubs then `go build`.

Run (root or CAP_NET_ADMIN needed for tc):
- ./quicfec-grpc-server

For safe testing, use scripts/demo_veth_ns.sh to create a netns + veth pair.
