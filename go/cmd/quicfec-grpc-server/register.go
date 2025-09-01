package main

import (
	"github.com/quic-go/quic-go/internal/env"
	"google.golang.org/grpc"
)

// registerEnv is a variable set by the grpc-tagged build to register the real gRPC service.
// By default (no grpcproto tag), it is a no-op so the binary builds without generated protos.
var registerEnv = func(_ *grpc.Server, _ *env.EnvServer) {}
