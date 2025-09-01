package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	pb "github.com/quic-go/quic-go/gen/github.com/quic-go/quic-go/gen/quicfec"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

func main() {
	var (
		addr    = flag.String("addr", "127.0.0.1:50051", "Env gRPC address")
		cmd     = flag.String("cmd", "configure", "command: configure|reset")
		dev     = flag.String("dev", "veth1", "device to shape")
		egress  = flag.Bool("egress", true, "apply on egress")
		ingress = flag.Bool("ingress", true, "apply on ingress via IFB")
		rtt     = flag.Float64("rtt", 40, "mean RTT ms")
		jitter  = flag.Float64("jitter", 5, "jitter ms")
		bw      = flag.Float64("bw", 50, "bandwidth Mbps (0=unlimited)")
		loss    = flag.Float64("loss", 0, "loss rate 0..1")
		reorder = flag.Float64("reorder", 0, "reorder rate 0..1")
	)
	flag.Parse()

	dial, err := grpc.Dial(*addr, grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	defer dial.Close()
	stub := pb.NewEnvClient(dial)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	switch *cmd {
	case "configure":
		cfg := &pb.ExperimentConfig{
			Scheme: pb.FecScheme_FEC_RAPTORQ,
			Net: &pb.NetScenario{
				Dev: *dev, UseEgress: *egress, UseIngress: *ingress,
				RttMsMean: float32(*rtt), RttJitterMs: float32(*jitter),
				BandwidthMbps: float32(*bw), LossRate: float32(*loss), ReorderRate: float32(*reorder),
			},
		}
		if _, err := stub.Configure(ctx, cfg); err != nil {
			panic(err)
		}
		fmt.Println("configured")
	case "reset":
		if _, err := stub.Reset(ctx, &emptypb.Empty{}); err != nil {
			panic(err)
		}
		fmt.Println("reset ok")
	default:
		panic("unknown cmd")
	}
}
