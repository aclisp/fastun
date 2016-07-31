package udp

import (
	"encoding/json"
	"fmt"

	"golang.org/x/net/context"

	"github.com/aclisp/fastun/backend"
	"github.com/aclisp/fastun/pkg/ip"
	"github.com/aclisp/fastun/subnet"
)

func init() {
	backend.Register("udp", New)
}

const (
	defaultPort = 8285
)

type UdpBackend struct {
	sm       subnet.Manager
	extIface *backend.ExternalInterface
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	be := UdpBackend{
		sm:       sm,
		extIface: extIface,
	}
	return &be, nil
}

func (be *UdpBackend) RegisterNetwork(ctx context.Context, netname string, config *subnet.Config) (backend.Network, error) {
	cfg := struct {
		Port int
	}{
		Port: defaultPort,
	}

	// Parse our configuration
	if len(config.Backend) > 0 {
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding UDP backend config: %v", err)
		}
	}

	// Acquire the lease form subnet manager
	attrs := subnet.LeaseAttrs{
		PublicIP: ip.FromIP(be.extIface.ExtAddr),
	}

	l, err := be.sm.AcquireLease(ctx, netname, &attrs)
	switch err {
	case nil:

	case context.Canceled, context.DeadlineExceeded:
		return nil, err

	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	// Tunnel's subnet is that of the whole overlay network (e.g. /16)
	// and not that of the individual host (e.g. /24)
	tunNet := ip.IP4Net{
		IP:        l.Subnet.IP,
		PrefixLen: config.Network.PrefixLen,
	}

	return newNetwork(netname, be.sm, be.extIface, cfg.Port, tunNet, l)
}

func (_ *UdpBackend) Run(ctx context.Context) {
	<-ctx.Done()
}
