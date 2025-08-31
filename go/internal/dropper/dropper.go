package dropper

import (
	"math/rand"
)

// Bernoulli implements a simple u<p drop decision.
type Bernoulli struct {
	p   float64
	rng *rand.Rand
}

func New(p float64, rng *rand.Rand) *Bernoulli { return &Bernoulli{p: p, rng: rng} }

func (b *Bernoulli) Drop() bool {
	if b.p <= 0 {
		return false
	}
	if b.p >= 1 {
		return true
	}
	return b.rng.Float64() < b.p
}
