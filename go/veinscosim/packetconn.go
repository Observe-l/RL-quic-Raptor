// Package veinscosim adapts QUIC's UDP datagrams to the local Veins WSM bridge.
// The adapter changes only where QUIC reads/writes UDP packets; QUIC, TLS, FEC,
// congestion control, stream, datagram, and ARQ logic remain in quic-go/fecquic.
package veinscosim

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	headerLen   = 9
	msgData     = 1
	msgRegister = 2
	serverID    = 0xffff
)

var magic = [4]byte{'V', 'Q', 'F', '1'}

// PacketConn is a net.PacketConn backed by the OMNeT++ UDP/WSM bridge.
type PacketConn struct {
	conn     *net.UDPConn
	server   bool
	id       uint16
	bridge   *net.UDPAddr
	local    net.Addr
	stop     chan struct{}
	closed   sync.Once
	register sync.WaitGroup
}

// ListenClient creates a vehicle endpoint. bridgePort is the local UDP port
// polled by that vehicle's Veins application; vehicleID is its SUMO/Veins index.
func ListenClient(vehicleID int, bridgePort int) (*PacketConn, error) {
	if vehicleID < 0 || vehicleID >= serverID {
		return nil, fmt.Errorf("vehicle id out of range: %d", vehicleID)
	}
	return listen(false, uint16(vehicleID), bridgePort)
}

// ListenServer creates the RSU endpoint. bridgePort is polled by the RSU app.
func ListenServer(bridgePort int) (*PacketConn, error) {
	return listen(true, serverID, bridgePort)
}

func listen(server bool, id uint16, bridgePort int) (*PacketConn, error) {
	if bridgePort < 1 || bridgePort > 65535 {
		return nil, fmt.Errorf("invalid bridge port %d", bridgePort)
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	p := &PacketConn{
		conn: c, server: server, id: id,
		bridge: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: bridgePort},
		stop:   make(chan struct{}),
	}
	if server {
		p.local = &net.UDPAddr{IP: net.IPv4(10, 77, 0, 1), Port: 4444}
	} else {
		p.local = &net.UDPAddr{IP: virtualIP(id), Port: 4444}
	}
	p.register.Add(1)
	go p.registerLoop()
	return p, nil
}

func (p *PacketConn) registerLoop() {
	defer p.register.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		_ = p.writeEnvelope(msgRegister, p.id, serverID, nil)
		select {
		case <-p.stop:
			return
		case <-ticker.C:
		}
	}
}

func (p *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	for {
		n, _, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < headerLen || string(buf[:4]) != string(magic[:]) || buf[4] != msgData {
			continue
		}
		src := binary.BigEndian.Uint16(buf[5:7])
		dst := binary.BigEndian.Uint16(buf[7:9])
		if p.server {
			if src == serverID || dst != serverID {
				continue
			}
		} else if src != serverID || dst != p.id {
			continue
		}
		payload := buf[headerLen:n]
		copied := copy(b, payload)
		if copied != len(payload) {
			return copied, nil, errors.New("QUIC datagram truncated by PacketConn buffer")
		}
		if p.server {
			return copied, &net.UDPAddr{IP: virtualIP(src), Port: 4444}, nil
		}
		return copied, &net.UDPAddr{IP: net.IPv4(10, 77, 0, 1), Port: 4444}, nil
	}
}

func (p *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	var dst uint16 = serverID
	if p.server {
		var ok bool
		dst, ok = vehicleID(addr)
		if !ok {
			return 0, fmt.Errorf("not a Veins vehicle address: %v", addr)
		}
	} else if !isServerAddr(addr) {
		return 0, fmt.Errorf("client can only send to the RSU: %v", addr)
	}
	if err := p.writeEnvelope(msgData, p.id, dst, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *PacketConn) writeEnvelope(kind byte, src, dst uint16, payload []byte) error {
	buf := make([]byte, headerLen+len(payload))
	copy(buf[:4], magic[:])
	buf[4] = kind
	binary.BigEndian.PutUint16(buf[5:7], src)
	binary.BigEndian.PutUint16(buf[7:9], dst)
	copy(buf[headerLen:], payload)
	_, err := p.conn.WriteToUDP(buf, p.bridge)
	return err
}

func (p *PacketConn) Close() error {
	var err error
	p.closed.Do(func() {
		close(p.stop)
		p.register.Wait()
		err = p.conn.Close()
	})
	return err
}

func (p *PacketConn) LocalAddr() net.Addr                { return p.local }
func (p *PacketConn) SetDeadline(t time.Time) error      { return p.conn.SetDeadline(t) }
func (p *PacketConn) SetReadDeadline(t time.Time) error  { return p.conn.SetReadDeadline(t) }
func (p *PacketConn) SetWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }

func isServerAddr(addr net.Addr) bool {
	a, ok := addr.(*net.UDPAddr)
	if !ok || a.Port != 4444 {
		return false
	}
	return a.IP.Equal(net.IPv4(10, 77, 0, 1))
}

func vehicleID(addr net.Addr) (uint16, bool) {
	a, ok := addr.(*net.UDPAddr)
	if !ok || a.Port != 4444 {
		return 0, false
	}
	ip := a.IP.To4()
	if ip == nil || ip[0] != 10 || ip[1] != 77 || ip[2] == 0 || ip[3] == 0 {
		return 0, false
	}
	id := int(ip[2]-1)*254 + int(ip[3]-1)
	if id >= int(serverID) {
		return 0, false
	}
	return uint16(id), true
}

func virtualIP(id uint16) net.IP {
	return net.IPv4(10, 77, byte(int(id)/254+1), byte(int(id)%254+1))
}
