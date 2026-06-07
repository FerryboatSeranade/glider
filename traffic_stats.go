package main

import (
	"sort"
	"sync"
	"sync/atomic"
)

type TrafficStat struct {
	Name    string `json:"name"`
	RXBytes uint64 `json:"rx_bytes"`
	TXBytes uint64 `json:"tx_bytes"`
}

type TrafficSnapshot struct {
	Users   []TrafficStat `json:"users,omitempty"`
	Rules   []TrafficStat `json:"rules,omitempty"`
	Dialers []TrafficStat `json:"dialers,omitempty"`
}

type trafficCounters struct {
	mu      sync.Mutex
	users   map[string]*trafficCounter
	rules   map[string]*trafficCounter
	dialers map[string]*trafficCounter
}

type trafficCounter struct {
	rx atomic.Uint64
	tx atomic.Uint64
}

var nodeTrafficCounters = &trafficCounters{
	users:   make(map[string]*trafficCounter),
	rules:   make(map[string]*trafficCounter),
	dialers: make(map[string]*trafficCounter),
}

func recordProxyTraffic(user, ruleName, dialer string, rx, tx uint64) {
	if rx == 0 && tx == 0 {
		return
	}
	nodeTrafficCounters.add(nodeTrafficCounters.users, user, rx, tx)
	nodeTrafficCounters.add(nodeTrafficCounters.rules, ruleName, rx, tx)
	nodeTrafficCounters.add(nodeTrafficCounters.dialers, dialer, rx, tx)
}

func proxyTrafficSnapshot() TrafficSnapshot {
	return TrafficSnapshot{
		Users:   nodeTrafficCounters.snapshot(nodeTrafficCounters.users),
		Rules:   nodeTrafficCounters.snapshot(nodeTrafficCounters.rules),
		Dialers: nodeTrafficCounters.snapshot(nodeTrafficCounters.dialers),
	}
}

func resetProxyTrafficCountersForTest() {
	nodeTrafficCounters.mu.Lock()
	defer nodeTrafficCounters.mu.Unlock()
	nodeTrafficCounters.users = make(map[string]*trafficCounter)
	nodeTrafficCounters.rules = make(map[string]*trafficCounter)
	nodeTrafficCounters.dialers = make(map[string]*trafficCounter)
}

func (c *trafficCounters) add(m map[string]*trafficCounter, name string, rx, tx uint64) {
	if name == "" {
		return
	}
	counter := c.get(m, name)
	counter.rx.Add(rx)
	counter.tx.Add(tx)
}

func (c *trafficCounters) get(m map[string]*trafficCounter, name string) *trafficCounter {
	c.mu.Lock()
	defer c.mu.Unlock()
	if counter := m[name]; counter != nil {
		return counter
	}
	counter := &trafficCounter{}
	m[name] = counter
	return counter
}

func (c *trafficCounters) snapshot(m map[string]*trafficCounter) []TrafficStat {
	c.mu.Lock()
	items := make([]TrafficStat, 0, len(m))
	for name, counter := range m {
		items = append(items, TrafficStat{
			Name:    name,
			RXBytes: counter.rx.Load(),
			TXBytes: counter.tx.Load(),
		})
	}
	c.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}
