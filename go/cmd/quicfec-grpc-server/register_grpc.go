//go:build grpcproto

package main

import (
	"context"

	pb "github.com/quic-go/quic-go/gen/github.com/quic-go/quic-go/gen/quicfec"
	"github.com/quic-go/quic-go/internal/env"
	"github.com/quic-go/quic-go/internal/sim"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// envGRPC wraps our env.EnvServer into the generated gRPC interface.
type envGRPC struct {
	pb.UnimplementedEnvServer
	inner *env.EnvServer
}

// Provide the concrete registration by assigning to the package-level variable from register.go.
func init() {
	registerEnv = func(grpcSrv *grpc.Server, inner *env.EnvServer) {
		pb.RegisterEnvServer(grpcSrv, &envGRPC{inner: inner})
	}
}

func netToSim(n *pb.NetScenario) *sim.NetScenario {
	if n == nil {
		return &sim.NetScenario{}
	}
	return &sim.NetScenario{
		Dev: n.Dev, UseEgress: n.UseEgress, UseIngress: n.UseIngress,
		RttMsMean: float32(n.RttMsMean), RttJitterMs: float32(n.RttJitterMs),
		BandwidthMbps: float32(n.BandwidthMbps), LossRate: float32(n.LossRate), ReorderRate: float32(n.ReorderRate),
	}
}

// pb.EnvServer implementation
func (e *envGRPC) Configure(ctx context.Context, cfg *pb.ExperimentConfig) (*emptypb.Empty, error) {
	// Map to placeholder env.ExperimentConfig
	ec := &env.ExperimentConfig{Net: *netToSim(cfg.Net)}
	if err := e.inner.Configure(ctx, ec); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (e *envGRPC) Reset(ctx context.Context, _ *emptypb.Empty) (*pb.Observation, error) {
	_, err := e.inner.Reset(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.Observation{}, nil
}

func (e *envGRPC) Rollout(stream pb.Env_RolloutServer) error {
	recv := func() (*env.StepRequest, error) {
		_, err := stream.Recv() // ignore action for now
		if err != nil {
			return nil, err
		}
		return &env.StepRequest{}, nil
	}
	send := func(_ *env.StepResponse) error {
		return stream.Send(&pb.StepResponse{})
	}
	return e.inner.Rollout(recv, send)
}
