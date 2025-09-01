package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	"github.com/quic-go/quic-go/internal/env"
	"github.com/quic-go/quic-go/internal/sim"
)

func main() {
	mgr := sim.NewNetemManager()
	defer mgr.Cleanup()

	// Trap signals to ensure cleanup
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-c; _ = mgr.Cleanup(); os.Exit(0) }()

	// Create Env server skeleton
	srv := env.NewEnvServer(mgr)

	// Start gRPC server
	ln, err := net.Listen("tcp", ":50051")
	if err != nil {
		fmt.Println("listen:", err)
		return
	}
	grpcSrv := grpc.NewServer()
	registerEnv(grpcSrv, srv)
	fmt.Println("quicfec gRPC control listening on :50051")
	if err := grpcSrv.Serve(ln); err != nil {
		fmt.Println("grpc serve:", err)
	}
}
