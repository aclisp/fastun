package network

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/golang/glog"

	"github.com/aclisp/fastun/pkg/ip"
)

func rules(ipn ip.IP4Net) [][]string {
	n := ipn.String()

	return [][]string{
		// This rule makes sure we don't NAT traffic within overlay network (e.g. coming out of docker0)
		{"-s", n, "-d", n, "-j", "ACCEPT"},
		// NAT if it's not multicast traffic
		{"-s", n, "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE"},
		// Masquerade anything headed towards flannel from the host
		//{"!", "-s", n, "-d", n, "-j", "MASQUERADE"},
	}
}

func setupIPMasq(ipn ip.IP4Net) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("failed to set up IP Masquerade. iptables was not found")
	}

	ruleList := rules(ipn)
	for i := len(ruleList) - 1; i >= 0; i-- {
		rule := ruleList[i]
		log.Info("Inserting at head iptables rule: ", strings.Join(rule, " "))
		err = ipt.InsertUnique("nat", "POSTROUTING", rule...)
		if err != nil {
			return fmt.Errorf("failed to insert IP masquerade rule: %v", err)
		}
	}

	return nil
}

func teardownIPMasq(ipn ip.IP4Net) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("failed to teardown IP Masquerade. iptables was not found")
	}

	for _, rule := range rules(ipn) {
		log.Info("Deleting iptables rule: ", strings.Join(rule, " "))
		err = ipt.Delete("nat", "POSTROUTING", rule...)
		if err != nil {
			return fmt.Errorf("failed to delete IP masquerade rule: %v", err)
		}
	}

	return nil
}
