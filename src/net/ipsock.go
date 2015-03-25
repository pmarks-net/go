// Copyright 2009 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Internet protocol family sockets

package net

import (
	"errors"
	"time"
)

var (
	// supportsIPv4 reports whether the platform supports IPv4
	// networking functionality.
	supportsIPv4 bool

	// supportsIPv6 reports whether the platform supports IPv6
	// networking functionality.
	supportsIPv6 bool

	// supportsIPv4map reports whether the platform supports
	// mapping an IPv4 address inside an IPv6 address at transport
	// layer protocols.  See RFC 4291, RFC 4038 and RFC 3493.
	supportsIPv4map bool
)

func init() {
	sysInit()
	supportsIPv4 = probeIPv4Stack()
	supportsIPv6, supportsIPv4map = probeIPv6Stack()
}


type addrWithTags struct {
	Addr
	// single should be true on exactly one item within an addrList,
	// to indicate that this address should be used by APIs that cannot
	// handle more than one.
	single   bool
	// fallback may be true on some (but not all) addresses in an addrList,
	// which moves them to the fallback thread when doing Happy Eyeballs.
	fallback bool
}

type addrList []addrWithTags

// makeAddrList constructs an addrList list of exactly one element.
func makeAddrList(addr Addr) addrList {
	return addrList{
		addrWithTags{
			Addr:     addr,
			single:   true,
			fallback: false,
		},
	}
}

// getSingle picks a single address, for legacy code that can't handle lists.
func (addrs addrList) getSingle() Addr {
	var out Addr
	count := 0
	for _, addr := range addrs {
		if addr.single {
			out = addr.Addr
			count++
		}
	}
	if count != 1 {
		panic("Malformed addrList: expected exactly 1 'single' tag")
	}
	return out
}

// getAll returns every address in order.
func (addrs addrList) getAll() []Addr {
	var out []Addr
	for _, addr := range addrs {
		out = append(out, addr.Addr)
	}
	return out
}

// getPrimaries returns only the addresses without a fallback tag.
// When doing Happy Eyeballs, these belong in the primary thread.
func (addrs addrList) getPrimaries() []Addr {
	var out []Addr
	for _, addr := range addrs {
		if !addr.fallback {
			out = append(out, addr.Addr)
		}
	}
	return out
}

// getFallbacks returns only the addresses with a fallback tag.
// When doing Happy Eyeballs, these belong in the delayed thread.
func (addrs addrList) getFallbacks() []Addr {
	var out []Addr
	for _, addr := range addrs {
		if addr.fallback {
			out = append(out, addr.Addr)
		}
	}
	return out
}


var errNoSuitableAddress = errors.New("no suitable address found")

// filterAndTagAddrs applies a filter to a list of IP addresses, and
// tags them for use by a Happy Eyeballs algorithm.  Known filters are
// nil, ipv4only, and ipv6only.  It returns all addresses when the
// filter is nil.  When error is nil, the resulting getSingle(),
// getPrimaries(), and getAll() will return at least one address.
func filterAndTagAddrs(filter func(IPAddr) bool, ips []IPAddr, inetaddr func(IPAddr) Addr) (addrList, error) {
	var (
		addrs     addrList
		v4Addrs   []int
		v6Addrs   []int
		fallbacks *[]int
	)
	for _, ip := range ips {
		if filter != nil && !filter(ip) {
			continue
		}
		if ipv4only(ip) {
			if fallbacks == nil {
				fallbacks = &v6Addrs
			}
			v4Addrs = append(v4Addrs, len(addrs))
			addrs = append(addrs, addrWithTags{Addr: inetaddr(ip)})
		} else if ipv6only(ip) {
			if fallbacks == nil {
				fallbacks = &v4Addrs
			}
			v6Addrs = append(v6Addrs, len(addrs))
			addrs = append(addrs, addrWithTags{Addr: inetaddr(ip)})
		}
	}
	// Tag the one address that getSingle() should return,
	// while preferring IPv4 for legacy compatibility.
	if len(v4Addrs) > 0 {
		addrs[v4Addrs[0]].single = true
	} else if len(v6Addrs) > 0 {
		addrs[v6Addrs[0]].single = true
	} else {
		return nil, errNoSuitableAddress
	}
	// Tag the fallback addresses.
	for _, i := range *fallbacks {
		addrs[i].fallback = true
	}
	return addrs, nil
}

// ipv4only returns IPv4 addresses that we can use with the kernel's
// IPv4 addressing modes. If ip is an IPv4 address, ipv4only returns true.
// Otherwise it returns false.
func ipv4only(addr IPAddr) bool {
	return supportsIPv4 && addr.IP.To4() != nil
}

// ipv6only returns IPv6 addresses that we can use with the kernel's
// IPv6 addressing modes.  It returns true for regular IPv6 addresses,
// and false for anything else (including IPv4-mapped IPv6.)
func ipv6only(addr IPAddr) bool {
	return supportsIPv6 && len(addr.IP) == IPv6len && addr.IP.To4() == nil
}

// SplitHostPort splits a network address of the form "host:port",
// "[host]:port" or "[ipv6-host%zone]:port" into host or
// ipv6-host%zone and port.  A literal address or host name for IPv6
// must be enclosed in square brackets, as in "[::1]:80",
// "[ipv6-host]:http" or "[ipv6-host%zone]:80".
func SplitHostPort(hostport string) (host, port string, err error) {
	j, k := 0, 0

	// The port starts after the last colon.
	i := last(hostport, ':')
	if i < 0 {
		goto missingPort
	}

	if hostport[0] == '[' {
		// Expect the first ']' just before the last ':'.
		end := byteIndex(hostport, ']')
		if end < 0 {
			err = &AddrError{"missing ']' in address", hostport}
			return
		}
		switch end + 1 {
		case len(hostport):
			// There can't be a ':' behind the ']' now.
			goto missingPort
		case i:
			// The expected result.
		default:
			// Either ']' isn't followed by a colon, or it is
			// followed by a colon that is not the last one.
			if hostport[end+1] == ':' {
				goto tooManyColons
			}
			goto missingPort
		}
		host = hostport[1:end]
		j, k = 1, end+1 // there can't be a '[' resp. ']' before these positions
	} else {
		host = hostport[:i]
		if byteIndex(host, ':') >= 0 {
			goto tooManyColons
		}
		if byteIndex(host, '%') >= 0 {
			goto missingBrackets
		}
	}
	if byteIndex(hostport[j:], '[') >= 0 {
		err = &AddrError{"unexpected '[' in address", hostport}
		return
	}
	if byteIndex(hostport[k:], ']') >= 0 {
		err = &AddrError{"unexpected ']' in address", hostport}
		return
	}

	port = hostport[i+1:]
	return

missingPort:
	err = &AddrError{"missing port in address", hostport}
	return

tooManyColons:
	err = &AddrError{"too many colons in address", hostport}
	return

missingBrackets:
	err = &AddrError{"missing brackets in address", hostport}
	return
}

func splitHostZone(s string) (host, zone string) {
	// The IPv6 scoped addressing zone identifier starts after the
	// last percent sign.
	if i := last(s, '%'); i > 0 {
		host, zone = s[:i], s[i+1:]
	} else {
		host = s
	}
	return
}

// JoinHostPort combines host and port into a network address of the
// form "host:port" or, if host contains a colon or a percent sign,
// "[host]:port".
func JoinHostPort(host, port string) string {
	// If host has colons or a percent sign, have to bracket it.
	if byteIndex(host, ':') >= 0 || byteIndex(host, '%') >= 0 {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// resolveInternetAddr resolves addr that is either a literal IP
// address or a DNS name and returns an internet protocol family
// address. It returns a list that contains a pair of different
// address family addresses when addr is a DNS name and the name has
// multiple address family records. The result contains at least one
// address when error is nil.
func resolveInternetAddrs(net, addr string, deadline time.Time) (addrList, error) {
	var (
		err        error
		host, port string
		portnum    int
	)
	switch net {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		if addr != "" {
			if host, port, err = SplitHostPort(addr); err != nil {
				return nil, err
			}
			if portnum, err = parsePort(net, port); err != nil {
				return nil, err
			}
		}
	case "ip", "ip4", "ip6":
		if addr != "" {
			host = addr
		}
	default:
		return nil, UnknownNetworkError(net)
	}
	inetaddr := func(ip IPAddr) Addr {
		switch net {
		case "tcp", "tcp4", "tcp6":
			return &TCPAddr{IP: ip.IP, Port: portnum, Zone: ip.Zone}
		case "udp", "udp4", "udp6":
			return &UDPAddr{IP: ip.IP, Port: portnum, Zone: ip.Zone}
		case "ip", "ip4", "ip6":
			return &IPAddr{IP: ip.IP, Zone: ip.Zone}
		default:
			panic("unexpected network: " + net)
		}
	}
	if host == "" {
		return makeAddrList(inetaddr(IPAddr{})), nil
	}
	// Try as a literal IP address.
	var ip IP
	if ip = parseIPv4(host); ip != nil {
		return makeAddrList(inetaddr(IPAddr{IP: ip})), nil
	}
	var zone string
	if ip, zone = parseIPv6(host, true); ip != nil {
		return makeAddrList(inetaddr(IPAddr{IP: ip, Zone: zone})), nil
	}
	// Try as a DNS name.
	ips, err := lookupIPDeadline(host, deadline)
	if err != nil {
		return nil, err
	}
	var filter func(IPAddr) bool
	if net != "" && net[len(net)-1] == '4' {
		filter = ipv4only
	}
	if net != "" && net[len(net)-1] == '6' {
		filter = ipv6only
	}
	return filterAndTagAddrs(filter, ips, inetaddr)
}

func zoneToString(zone int) string {
	if zone == 0 {
		return ""
	}
	if ifi, err := InterfaceByIndex(zone); err == nil {
		return ifi.Name
	}
	return uitoa(uint(zone))
}

func zoneToInt(zone string) int {
	if zone == "" {
		return 0
	}
	if ifi, err := InterfaceByName(zone); err == nil {
		return ifi.Index
	}
	n, _, _ := dtoi(zone, 0)
	return n
}
