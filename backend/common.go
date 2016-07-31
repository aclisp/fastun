package backend

import (
	"net"

	"golang.org/x/net/context"

	"github.com/aclisp/fastun/subnet"
)

type ExternalInterface struct {
	Iface     *net.Interface
	IfaceAddr net.IP
	ExtAddr   net.IP
}

// Besides the entry points in the Backend interface, the backend's New()
// function receives static network interface information (like internal and
// external IP addresses, MTU, etc) which it should cache for later use if
// needed.
//
// To implement a singleton backend which manages multiple networks, the
// New() function should create the singleton backend object once, and return
// that object on on further calls to New().  The backend is guaranteed that
// the arguments passed via New() will not change across invocations.  Also,
// since multiple RegisterNetwork() and Run() calls may be in-flight at any
// given time for a singleton backend, it must protect these calls with a mutex.
type Backend interface {
	// Called first to start the necessary event loops and such
	Run(ctx context.Context)
	// Called when the backend should create or begin managing a new network
	RegisterNetwork(ctx context.Context, network string, config *subnet.Config) (Network, error)
}

type Network interface {
	Lease() *subnet.Lease
	MTU() int
	Run(ctx context.Context)
}

type BackendCtor func(sm subnet.Manager, ei *ExternalInterface) (Backend, error)

type SimpleNetwork struct {
	SubnetLease *subnet.Lease
	ExtIface    *ExternalInterface
}

func (n *SimpleNetwork) Lease() *subnet.Lease {
	return n.SubnetLease
}

func (n *SimpleNetwork) MTU() int {
	return n.ExtIface.Iface.MTU
}

func (_ *SimpleNetwork) Run(ctx context.Context) {
	<-ctx.Done()
}
