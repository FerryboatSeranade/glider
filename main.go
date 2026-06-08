package main

import (
	"context"
	"net"
	"net/netip"
	"os/signal"
	"syscall"
	"time"

	"github.com/nadoo/glider/dns"
	"github.com/nadoo/glider/ipset"
	"github.com/nadoo/glider/pkg/log"
	"github.com/nadoo/glider/proxy"
	"github.com/nadoo/glider/rule"
	"github.com/nadoo/glider/service"
)

var (
	version = "0.17.0"
)

func main() {
	config := parseConfig()
	rule.SetTrafficRecorder(recordProxyTraffic)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var (
		pxySw    *proxy.Switcher
		applier  *ConfigApplier
		nodeSync *NodeSyncer
	)

	if shouldRunDataPlane(config) {
		pxySw = proxy.NewSwitcher(rule.NewProxy(config.Forwards, &config.Strategy, nil))
		applier = NewConfigApplier(config, pxySw)

		if shouldRunNodeSync(config.Mode) {
			nodeSync = NewNodeSyncer(config, applier)
			if err := nodeSync.LoadCache(ctx); err != nil {
				log.Printf("[node] cached config unavailable: %v", err)
			}
		}

		if len(config.rules) == 0 {
			if err := loadRules(config); err != nil {
				log.Fatal(err)
			}
		}
		runDataPlane(config, pxySw)
	}

	if shouldRunAdmin(config.Mode) {
		startAdminServer(config, pxySw, applier)
	}

	if nodeSync != nil {
		nodeSync.Start(ctx)
	}

	<-ctx.Done()
}

func runDataPlane(config *Config, pxySw *proxy.Switcher) {
	// global rule proxy
	pxy := rule.NewProxy(config.Forwards, &config.Strategy, config.rules)
	pxySw.Set(pxy)

	// ipset manager
	ipsetM, _ := ipset.NewManager(config.rules)

	// check and setup dns server
	if config.DNS != "" {
		d, err := dns.NewServer(config.DNS, pxySw, &config.DNSConfig)
		if err != nil {
			log.Fatal(err)
		}

		// rules
		for _, r := range config.rules {
			if len(r.DNSServers) > 0 {
				for _, domain := range r.Domain {
					d.SetServers(domain, r.DNSServers)
				}
			}
		}

		// add a handler to update proxy rules when a domain resolved
		d.AddHandler(func(domain string, ip netip.Addr) error {
			if cur, ok := pxySw.Current().(*rule.Proxy); ok {
				return cur.AddDomainIP(domain, ip)
			}
			return nil
		})
		if ipsetM != nil {
			d.AddHandler(ipsetM.AddDomainIP)
		}

		d.Start()

		// custom resolver
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: time.Second * 3}
				return d.DialContext(ctx, "udp", config.DNS)
			},
		}
	}

	for _, r := range config.rules {
		r.IP, r.CIDR, r.Domain, r.User = nil, nil, nil, nil
	}

	// enable checkers
	pxy.Check()

	// run proxy servers
	for _, listen := range config.Listens {
		local, err := proxy.ServerFromURL(listen, pxySw)
		if err != nil {
			log.Fatal(err)
		}
		go local.ListenAndServe()
	}

	// run services
	for _, s := range config.Services {
		service, err := service.New(s)
		if err != nil {
			log.Fatal(err)
		}
		go service.Run()
	}
}
