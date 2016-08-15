package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/coreos/pkg/flagutil"
	log "github.com/golang/glog"
	"golang.org/x/net/context"

	"github.com/aclisp/fastun/network"
	"github.com/aclisp/fastun/pkg/sysctl"
	"github.com/aclisp/fastun/remote"
	"github.com/aclisp/fastun/subnet"
	"github.com/aclisp/fastun/version"

	// Backends need to be imported for their init() to get executed and them to register
	_ "github.com/aclisp/fastun/backend/udp"
)

type CmdLineOpts struct {
	etcdEndpoints  string
	etcdPrefix     string
	etcdKeyfile    string
	etcdCertfile   string
	etcdCAFile     string
	help           bool
	version        bool
	listen         string
	remote         string
	remoteKeyfile  string
	remoteCertfile string
	remoteCAFile   string
}

var opts CmdLineOpts

func init() {
	flag.StringVar(&opts.etcdEndpoints, "etcd-endpoints", "http://127.0.0.1:4001,http://127.0.0.1:2379", "a comma-delimited list of etcd endpoints")
	flag.StringVar(&opts.etcdPrefix, "etcd-prefix", "/coreos.com/network", "etcd prefix")
	flag.StringVar(&opts.etcdKeyfile, "etcd-keyfile", "", "SSL key file used to secure etcd communication")
	flag.StringVar(&opts.etcdCertfile, "etcd-certfile", "", "SSL certification file used to secure etcd communication")
	flag.StringVar(&opts.etcdCAFile, "etcd-cafile", "", "SSL Certificate Authority file used to secure etcd communication")
	flag.StringVar(&opts.listen, "listen", "", "run as server and listen on specified address (e.g. ':8080')")
	flag.StringVar(&opts.remote, "remote", "", "run as client and connect to server on specified address (e.g. '10.1.2.3:8080')")
	flag.StringVar(&opts.remoteKeyfile, "remote-keyfile", "", "SSL key file used to secure client/server communication")
	flag.StringVar(&opts.remoteCertfile, "remote-certfile", "", "SSL certification file used to secure client/server communication")
	flag.StringVar(&opts.remoteCAFile, "remote-cafile", "", "SSL Certificate Authority file used to secure client/server communication")
	flag.BoolVar(&opts.help, "help", false, "print this message")
	flag.BoolVar(&opts.version, "version", false, "print version and exit")
}

func newSubnetManager() (subnet.Manager, error) {
	if opts.remote != "" {
		return remote.NewRemoteManager(opts.remote, opts.remoteCAFile, opts.remoteCertfile, opts.remoteKeyfile)
	}

	cfg := &subnet.EtcdConfig{
		Endpoints: strings.Split(opts.etcdEndpoints, ","),
		Keyfile:   opts.etcdKeyfile,
		Certfile:  opts.etcdCertfile,
		CAFile:    opts.etcdCAFile,
		Prefix:    opts.etcdPrefix,
	}

	return subnet.NewLocalManager(cfg)
}

func restrictToSingleInstance() {
	_, err := net.Listen("tcp", "127.0.0.1:61234")
	if err != nil {
		panic(err)
	}
}

func main() {
	// Prevent unnecessary subnet update, which could reset KCP on the wire
	restrictToSingleInstance()

	// glog will log to tmp files by default. override so all entries
	// can flow into journald (if running under systemd)
	flag.Set("logtostderr", "true")

	// now parse command line args
	flag.Parse()

	if flag.NArg() > 0 || opts.help {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]...\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(0)
	}

	if opts.version {
		fmt.Fprintln(os.Stderr, version.Version)
		os.Exit(0)
	}

	flagutil.SetFlagsFromEnv(flag.CommandLine, "TUNNELD")

	sysctl.SetSysctl(sysctl.NetCoreRmemMax, sysctl.NetCoreRmemMax64M)
	sysctl.SetSysctl(sysctl.NetCoreWmemMax, sysctl.NetCoreWmemMax64M)
	sysctl.SetSysctlString(sysctl.NetIpv4TcpMem, sysctl.NetIpv4TcpMem64M)
	sysctl.SetSysctlString(sysctl.NetIpv4UdpMem, sysctl.NetIpv4UdpMem64M)
	sysctl.SetSysctlMax(sysctl.NetIpv4TcpRmem, sysctl.NetIpv4TcpRmemMax64M)
	sysctl.SetSysctlMax(sysctl.NetIpv4TcpWmem, sysctl.NetIpv4TcpWmemMax64M)

	sm, err := newSubnetManager()
	if err != nil {
		log.Error("Failed to create SubnetManager: ", err)
		os.Exit(1)
	}

	// Register for SIGINT and SIGTERM
	log.Info("Installing signal handlers")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	var runFunc func(ctx context.Context)

	if opts.listen != "" {
		if opts.remote != "" {
			log.Error("--listen and --remote are mutually exclusive")
			os.Exit(1)
		}
		log.Info("running as server")
		runFunc = func(ctx context.Context) {
			remote.RunServer(ctx, sm, opts.listen, opts.remoteCAFile, opts.remoteCertfile, opts.remoteKeyfile)
		}
	} else {
		nm, err := network.NewNetworkManager(ctx, sm)
		if err != nil {
			log.Error("Failed to create NetworkManager: ", err)
			os.Exit(1)
		}

		runFunc = func(ctx context.Context) {
			nm.Run(ctx)
		}
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		runFunc(ctx)
		wg.Done()
	}()

	<-sigs
	// unregister to get default OS nuke behaviour in case we don't exit cleanly
	signal.Stop(sigs)

	log.Info("Exiting...")
	cancel()

	wg.Wait()
}
