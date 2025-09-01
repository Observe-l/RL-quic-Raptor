package env

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/quic-go/quic-go/internal/sim"
)

// We avoid importing the generated proto now to keep this file compiling before protoc runs.
// Define minimal interfaces compatible with the generated types and replace later.

type Netem interface {
	Apply(*sim.NetScenario) error
	Update(*sim.NetScenario) error
	Cleanup() error
}

// ExperimentConfig placeholder. Replace with pb.ExperimentConfig when stubs exist.
type ExperimentConfig struct {
	Net sim.NetScenario
}

// Observation placeholder
type Observation struct{}

// StepRequest/Response placeholder
type Action struct{}
type StepRequest struct{ Action Action }
type StepMetrics struct{}
type StepResponse struct {
	Obs     Observation
	Reward  float64
	Done    bool
	Metrics StepMetrics
}

// EnvServer is a minimal skeleton to be wired with generated gRPC later.
type EnvServer struct {
	netem Netem
	cfg   *ExperimentConfig
}

func NewEnvServer(netem Netem) *EnvServer { return &EnvServer{netem: netem} }

func (s *EnvServer) Configure(ctx context.Context, cfg *ExperimentConfig) error {
	if err := s.netem.Apply(&cfg.Net); err != nil {
		return err
	}
	s.cfg = cfg
	return nil
}

func (s *EnvServer) Reset(ctx context.Context) (*Observation, error) {
	if s.cfg != nil {
		if err := s.netem.Update(&s.cfg.Net); err != nil {
			return nil, err
		}
	}
	return &Observation{}, nil
}

func (s *EnvServer) Rollout(streamRecv func() (*StepRequest, error), streamSend func(*StepResponse) error) error {
	ticker := time.NewTicker(64 * time.Millisecond)
	defer ticker.Stop()
	for {
		req, err := streamRecv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		_ = req // TODO: apply action to QUIC/FEC
		<-ticker.C
		resp := &StepResponse{Obs: Observation{}, Reward: 0, Done: false, Metrics: StepMetrics{}}
		if err := streamSend(resp); err != nil {
			return err
		}
		if resp.Done {
			return nil
		}
	}
}
