//go:build quicfecdev

package fecquic

import (
	"fmt"
	"os"
)

func init() {
	// Override hook declared in dev_ddl_default.go.
	devLogRxDDLHook = func(msg string, args ...any) {
		if os.Getenv("QUIC_FEC_DEV_DDL") != "1" {
			return
		}
		fmt.Fprintf(os.Stderr, "[dev-ddl] "+msg+"\n", args...)
	}
}
