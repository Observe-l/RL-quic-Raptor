package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/quic-go/quic-go/fecquic"
)

func main() {
	var (
		addr     = flag.String("addr", "127.0.0.1:4444", "server address")
		alpn     = flag.String("alpn", "quic-fec", "ALPN protocol")
		filePath = flag.String("file", "go/test_data/train_FD001.txt", "file to send")
		insecure = flag.Bool("insecure", true, "skip TLS verification")
		N        = flag.Int("N", 32, "block length N")
		K        = flag.Int("K", 26, "source symbols K")
		L        = flag.Int("L", 1200, "symbol bytes L")
		loss     = flag.Float64("loss", 0.0, "sender drop probability (simulate)")
		pace     = flag.Duration("pace", 0, "sleep between datagrams")
		blkPause = flag.Duration("block-pause", 0, "sleep after each block")
		warn     = flag.Int("dgram-warn", 0, "warn if datagram exceeds bytes (0=off)")
		postWait = flag.Duration("post-wait", 0, "linger after sending to allow server to finalize")
	)
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	opts := fecquic.SendOptions{K: *K, N: *N, L: *L, InsecureTLS: *insecure, DropProb: *loss, PaceEach: *pace, BlockPause: *blkPause, WarnDgramSize: *warn, PostWait: *postWait}
	if err := fecquic.ClientSendFile(ctx, *addr, *alpn, *filePath, opts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
