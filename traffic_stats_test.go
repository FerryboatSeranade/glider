package main

import "testing"

func TestProxyTrafficSnapshotSortsAndAggregates(t *testing.T) {
	resetProxyTrafficCountersForTest()
	recordProxyTraffic("bob", "rule-b", "dialer-b", 10, 20)
	recordProxyTraffic("alice", "rule-a", "dialer-a", 5, 7)
	recordProxyTraffic("bob", "rule-b", "dialer-b", 1, 2)

	snap := proxyTrafficSnapshot()
	if len(snap.Users) != 2 || snap.Users[0].Name != "alice" || snap.Users[1].Name != "bob" {
		t.Fatalf("users not sorted: %#v", snap.Users)
	}
	if snap.Users[1].RXBytes != 11 || snap.Users[1].TXBytes != 22 {
		t.Fatalf("bob totals = %#v", snap.Users[1])
	}
	if len(snap.Rules) != 2 || snap.Rules[1].RXBytes != 11 || snap.Rules[1].TXBytes != 22 {
		t.Fatalf("rule totals = %#v", snap.Rules)
	}
	if len(snap.Dialers) != 2 || snap.Dialers[1].RXBytes != 11 || snap.Dialers[1].TXBytes != 22 {
		t.Fatalf("dialer totals = %#v", snap.Dialers)
	}
}
