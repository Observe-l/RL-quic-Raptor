package sim

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// NetScenario matches the subset of fields needed for tc netem/htb control.
type NetScenario struct {
	Dev           string
	UseEgress     bool
	UseIngress    bool
	RttMsMean     float32
	RttJitterMs   float32
	BandwidthMbps float32
	LossRate      float32
	ReorderRate   float32
}

// NetemManager applies Linux tc netem/htb rules for a given device, optionally through IFB for ingress.
type NetemManager struct {
	dev         string
	ifb         string
	egUnlimited bool
	inUnlimited bool
}

func NewNetemManager() *NetemManager { return &NetemManager{} }

func (m *NetemManager) Apply(net *NetScenario) error {
	if net == nil {
		return nil
	}
	m.dev = net.Dev
	if m.dev == "" {
		return fmt.Errorf("netem: device not set")
	}
	// Egress
	if net.UseEgress {
		m.egUnlimited = net.BandwidthMbps <= 0
		if m.egUnlimited {
			if err := m.replaceRootNetem(m.dev, net); err != nil {
				return err
			}
		} else {
			if err := m.replaceRootHTB(m.dev, net.BandwidthMbps); err != nil {
				return err
			}
			if err := m.replaceNetem(m.dev, "1:1", net); err != nil {
				return err
			}
		}
	}
	// Ingress via IFB
	if net.UseIngress {
		if err := m.ensureIFB(); err != nil {
			return err
		}
		if err := m.redirectIngressToIFB(m.dev, m.ifb); err != nil {
			return err
		}
		m.inUnlimited = net.BandwidthMbps <= 0
		if m.inUnlimited {
			if err := m.replaceRootNetem(m.ifb, net); err != nil {
				return err
			}
		} else {
			if err := m.replaceRootHTB(m.ifb, net.BandwidthMbps); err != nil {
				return err
			}
			if err := m.replaceNetem(m.ifb, "2:1", net); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *NetemManager) Update(net *NetScenario) error {
	if net == nil {
		return nil
	}
	if net.UseEgress {
		if m.egUnlimited {
			if err := m.replaceRootNetem(m.dev, net); err != nil {
				return err
			}
		} else {
			if err := m.replaceNetem(m.dev, "1:1", net); err != nil {
				return err
			}
		}
	}
	if net.UseIngress {
		if m.inUnlimited {
			if err := m.replaceRootNetem(m.ifb, net); err != nil {
				return err
			}
		} else {
			if err := m.replaceNetem(m.ifb, "2:1", net); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *NetemManager) Cleanup() error {
	_ = run("tc", "qdisc", "del", "dev", m.dev, "root")
	_ = run("tc", "qdisc", "del", "dev", m.dev, "ingress")
	if m.ifb != "" {
		_ = run("tc", "qdisc", "del", "dev", m.ifb, "root")
		_ = run("ip", "link", "set", m.ifb, "down")
		_ = run("ip", "link", "del", m.ifb)
	}
	return nil
}

func (m *NetemManager) replaceRootHTB(dev string, mbps float32) error {
	if mbps <= 0 { // unlimited
		return run("tc", "qdisc", "replace", "dev", dev, "root", "handle", "10:", "netem")
	}
	if err := run("tc", "qdisc", "replace", "dev", dev, "root", "handle", "1:", "htb", "default", "1"); err != nil {
		return err
	}
	rate := fmt.Sprintf("%.0fmbit", mbps)
	if err := run("tc", "class", "replace", "dev", dev, "parent", "1:", "classid", "1:1", "htb", "rate", rate, "ceil", rate); err != nil {
		return err
	}
	return nil
}

func (m *NetemManager) replaceNetem(dev, parent string, net *NetScenario) error {
	delay := fmt.Sprintf("%.2fms", net.RttMsMean)
	jitter := fmt.Sprintf("%.2fms", net.RttJitterMs)
	loss := fmt.Sprintf("%.3f%%", net.LossRate*100.0)
	args := []string{"qdisc", "replace", "dev", dev, "parent", parent, "handle", "100:", "netem", "delay", delay, jitter, "loss", loss}
	if net.ReorderRate > 0 {
		args = append(args, "reorder", fmt.Sprintf("%.2f%%", net.ReorderRate*100.0), "gap", "5")
	}
	return run("tc", args...)
}

func (m *NetemManager) replaceRootNetem(dev string, net *NetScenario) error {
	delay := fmt.Sprintf("%.2fms", net.RttMsMean)
	jitter := fmt.Sprintf("%.2fms", net.RttJitterMs)
	loss := fmt.Sprintf("%.3f%%", net.LossRate*100.0)
	args := []string{"qdisc", "replace", "dev", dev, "root", "handle", "10:", "netem", "delay", delay, jitter, "loss", loss}
	if net.ReorderRate > 0 {
		args = append(args, "reorder", fmt.Sprintf("%.2f%%", net.ReorderRate*100.0), "gap", "5")
	}
	return run("tc", args...)
}

func (m *NetemManager) ensureIFB() error {
	m.ifb = "ifb0"
	_ = run("modprobe", "ifb", "numifbs=1")
	_ = run("ip", "link", "add", m.ifb, "type", "ifb")
	if err := run("ip", "link", "set", m.ifb, "up"); err != nil {
		return err
	}
	return nil
}

func (m *NetemManager) redirectIngressToIFB(dev, ifb string) error {
	if err := run("tc", "qdisc", "replace", "dev", dev, "handle", "ffff:", "ingress"); err != nil {
		return err
	}
	return run("tc", "filter", "replace", "dev", dev, "parent", "ffff:", "protocol", "all",
		"u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", ifb)
}

func run(cmd string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, cmd, args...)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %v\n%s", cmd, args, err, string(out))
	}
	return nil
}
