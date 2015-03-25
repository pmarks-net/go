// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"reflect"
	"testing"
)

var testInetaddr = func(ip IPAddr) Addr { return &TCPAddr{IP: ip.IP, Port: 5682, Zone: ip.Zone} }

var filterAndTagAddrsTests = []struct {
	filter     func(IPAddr) bool
	ips        []IPAddr
	inetaddr   func(IPAddr) Addr
	singleAddr Addr
	primaries  []Addr
	fallbacks  []Addr
	err      error
}{
	{
		nil,
		[]IPAddr{
			{IP: IPv4(127, 0, 0, 1)},
			{IP: IPv6loopback},
		},
		testInetaddr,
		&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
		[]Addr{&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682}},
		[]Addr{&TCPAddr{IP: IPv6loopback, Port: 5682}},
		nil,
	},
	{
		nil,
		[]IPAddr{
			{IP: IPv6loopback},
			{IP: IPv4(127, 0, 0, 1)},
		},
		testInetaddr,
		&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
		[]Addr{&TCPAddr{IP: IPv6loopback, Port: 5682}},
		[]Addr{&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682}},
		nil,
	},
	{
		nil,
		[]IPAddr{
			{IP: IPv4(127, 0, 0, 1)},
			{IP: IPv4(192, 168, 0, 1)},
		},
		testInetaddr,
		&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
		[]Addr{
			&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
			&TCPAddr{IP: IPv4(192, 168, 0, 1), Port: 5682},
		},
		nil,
		nil,
	},
	{
		nil,
		[]IPAddr{
			{IP: IPv6loopback},
			{IP: ParseIP("fe80::1"), Zone: "eth0"},
		},
		testInetaddr,
		&TCPAddr{IP: IPv6loopback, Port: 5682},
		[]Addr{
			&TCPAddr{IP: IPv6loopback, Port: 5682},
			&TCPAddr{IP: ParseIP("fe80::1"), Port: 5682, Zone: "eth0"},
		},
		nil,
		nil,
	},
	{
		nil,
		[]IPAddr{
			{IP: IPv4(127, 0, 0, 1)},
			{IP: IPv4(192, 168, 0, 1)},
			{IP: IPv6loopback},
			{IP: ParseIP("fe80::1"), Zone: "eth0"},
		},
		testInetaddr,
		&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
		[]Addr{
			&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
			&TCPAddr{IP: IPv4(192, 168, 0, 1), Port: 5682},
		},
		[]Addr{
			&TCPAddr{IP: IPv6loopback, Port: 5682},
			&TCPAddr{IP: ParseIP("fe80::1"), Port: 5682, Zone: "eth0"},
		},
		nil,
	},
	{
		nil,
		[]IPAddr{
			{IP: IPv6loopback},
			{IP: ParseIP("fe80::1"), Zone: "eth0"},
			{IP: IPv4(127, 0, 0, 1)},
			{IP: IPv4(192, 168, 0, 1)},
		},
		testInetaddr,
		&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
		[]Addr{
			&TCPAddr{IP: IPv6loopback, Port: 5682},
			&TCPAddr{IP: ParseIP("fe80::1"), Port: 5682, Zone: "eth0"},
		},
		[]Addr{
			&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
			&TCPAddr{IP: IPv4(192, 168, 0, 1), Port: 5682},
		},
		nil,
	},
	{
		nil,
		[]IPAddr{
			{IP: IPv4(127, 0, 0, 1)},
			{IP: IPv6loopback},
			{IP: IPv4(192, 168, 0, 1)},
			{IP: ParseIP("fe80::1"), Zone: "eth0"},
		},
		testInetaddr,
		&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
		[]Addr{
			&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
			&TCPAddr{IP: IPv4(192, 168, 0, 1), Port: 5682},
		},
		[]Addr{
			&TCPAddr{IP: IPv6loopback, Port: 5682},
			&TCPAddr{IP: ParseIP("fe80::1"), Port: 5682, Zone: "eth0"},
		},
		nil,
	},
	{
		nil,
		[]IPAddr{
			{IP: IPv6loopback},
			{IP: IPv4(127, 0, 0, 1)},
			{IP: ParseIP("fe80::1"), Zone: "eth0"},
			{IP: IPv4(192, 168, 0, 1)},
		},
		testInetaddr,
		&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
		[]Addr{
			&TCPAddr{IP: IPv6loopback, Port: 5682},
			&TCPAddr{IP: ParseIP("fe80::1"), Port: 5682, Zone: "eth0"},
		},
		[]Addr{
			&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
			&TCPAddr{IP: IPv4(192, 168, 0, 1), Port: 5682},
		},
		nil,
	},

	{
		ipv4only,
		[]IPAddr{
			{IP: IPv4(127, 0, 0, 1)},
			{IP: IPv6loopback},
		},
		testInetaddr,
		&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
		[]Addr{&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682}},
		nil,
		nil,
	},
	{
		ipv4only,
		[]IPAddr{
			{IP: IPv6loopback},
			{IP: IPv4(127, 0, 0, 1)},
		},
		testInetaddr,
		&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682},
		[]Addr{&TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 5682}},
		nil,
		nil,
	},

	{
		ipv6only,
		[]IPAddr{
			{IP: IPv4(127, 0, 0, 1)},
			{IP: IPv6loopback},
		},
		testInetaddr,
		&TCPAddr{IP: IPv6loopback, Port: 5682},
		[]Addr{&TCPAddr{IP: IPv6loopback, Port: 5682}},
		nil,
		nil,
	},
	{
		ipv6only,
		[]IPAddr{
			{IP: IPv6loopback},
			{IP: IPv4(127, 0, 0, 1)},
		},
		testInetaddr,
		&TCPAddr{IP: IPv6loopback, Port: 5682},
		[]Addr{&TCPAddr{IP: IPv6loopback, Port: 5682}},
		nil,
		nil,
	},

	{nil, nil, testInetaddr, nil, nil, nil, errNoSuitableAddress},

	{ipv4only, nil, testInetaddr, nil, nil, nil, errNoSuitableAddress},
	{ipv4only, []IPAddr{IPAddr{IP: IPv6loopback}}, testInetaddr, nil, nil, nil, errNoSuitableAddress},

	{ipv6only, nil, testInetaddr, nil, nil, nil, errNoSuitableAddress},
	{ipv6only, []IPAddr{IPAddr{IP: IPv4(127, 0, 0, 1)}}, testInetaddr, nil, nil, nil, errNoSuitableAddress},
}

func TestFilterAndTagAddrs(t *testing.T) {
	if !supportsIPv4 || !supportsIPv6 {
		t.Skip("ipv4 or ipv6 is not supported")
	}

	for i, tt := range filterAndTagAddrsTests {
		addrs, err := filterAndTagAddrs(tt.filter, tt.ips, tt.inetaddr)
		if err != tt.err {
			t.Errorf("#%v: got err %v; expected %v", i, err, tt.err)
		}
		if tt.err != nil {
			if len(addrs) != 0 {
				t.Errorf("#%v: got %v addrs, expected 0", len(addrs))
			}
			continue
		}
		singleAddr := addrs.getSingle()
		if !reflect.DeepEqual(singleAddr, tt.singleAddr) {
			t.Errorf("#%v: got singleAddr %v; expected %v", i, singleAddr, tt.singleAddr)
		}
		primaries := addrs.getPrimaries()
		if !reflect.DeepEqual(primaries, tt.primaries) {
			t.Errorf("#%v: got primaries %v; expected %v", i, primaries, tt.primaries)
		}
		fallbacks := addrs.getFallbacks()
		if !reflect.DeepEqual(fallbacks, tt.fallbacks) {
			t.Errorf("#%v: got fallbacks %v; expected %v", i, fallbacks, tt.fallbacks)
		}
		allCount := len(addrs.getAll())
		expectedAllCount := len(primaries) + len(fallbacks)
		if allCount != expectedAllCount {
			t.Errorf("#%v: got %v addrs from getAll(); expected %v", i, allCount, expectedAllCount)
		}
	}
}
