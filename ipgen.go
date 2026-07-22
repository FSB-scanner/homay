package main

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
)

func ipToU32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func u32ToStr(u uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}

type ipRange struct {
	first uint32
	last  uint32
}

func parseCIDRs(cidrs []string) ([]ipRange, uint64, error) {
	var ranges []ipRange
	var total uint64
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			c = c + "/32"
		}
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			return nil, 0, fmt.Errorf("bad CIDR %s: %w", c, err)
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			continue
		}
		if ones < 10 {
			return nil, 0, fmt.Errorf("CIDR too large (min /10): %s", c)
		}
		base := ipToU32(ip4)
		size := uint32(1) << uint(32-ones)
		first := base
		last := base + size - 1
		// remove network/broadcast addresses for subnets larger than /30
		if ones <= 30 && size >= 4 {
			first = base + 1
			last = base + size - 2
		}
		if last < first {
			continue
		}
		ranges = append(ranges, ipRange{first, last})
		total += uint64(last-first) + 1
	}
	if len(ranges) == 0 {
		return nil, 0, fmt.Errorf("no valid IPv4 CIDRs")
	}
	return ranges, total, nil
}

// maxExpandIPs is the threshold above which a memory warning is shown.
const maxExpandIPs = 500_000

// expandAll returns every IP from all ranges, optionally shuffled.
func expandAll(ranges []ipRange, total uint64, rng *rand.Rand) []string {
	if total > maxExpandIPs {
		warn(fmt.Sprintf(
			"expanding %d IPs into memory — may be slow on mobile. Use -sample N to limit.",
			total,
		))
	}
	out := make([]string, 0, total)
	for _, r := range ranges {
		for u := r.first; u <= r.last; u++ {
			out = append(out, u32ToStr(u))
			if u == r.last {
				break
			}
		}
	}
	if rng != nil {
		rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	}
	return out
}

// sampleAcrossCIDRs picks n unique random IPs weighted by CIDR size.
// Uses Floyd's sampling algorithm: O(n) time, O(n) memory.
// n=0 means return all IPs (full expand).
func sampleAcrossCIDRs(cidrs []string, n int, rng *rand.Rand) ([]string, error) {
	ranges, total, err := parseCIDRs(cidrs)
	if err != nil {
		return nil, err
	}

	// full expand: n=0 or requested more than available
	if n <= 0 || uint64(n) >= total {
		return expandAll(ranges, total, rng), nil
	}

	// Floyd's sampling: select n unique indices from [0, total-1]
	// Time: O(n)  Memory: O(n)  — no need to iterate all 1.5M IPs
	chosen := make(map[int64]struct{}, n)
	for j := int64(total) - int64(n); j < int64(total); j++ {
		t := rng.Int63n(j + 1)
		if _, exists := chosen[t]; !exists {
			chosen[t] = struct{}{}
		} else {
			chosen[j] = struct{}{}
		}
	}

	// sort indices so we can binary-search the prefix array
	idxs := make([]int64, 0, n)
	for idx := range chosen {
		idxs = append(idxs, idx)
	}
	sort.Slice(idxs, func(i, j int) bool { return idxs[i] < idxs[j] })

	// build prefix-sum array for O(log m) index-to-IP mapping
	m := len(ranges)
	prefix := make([]uint64, m)
	for i, r := range ranges {
		size := uint64(r.last-r.first) + 1
		if i == 0 {
			prefix[i] = size
		} else {
			prefix[i] = prefix[i-1] + size
		}
	}

	// map each chosen index to its IP via binary search
	result := make([]string, 0, n)
	for _, id := range idxs {
		idx := uint64(id)
		i := sort.Search(m, func(i int) bool { return prefix[i] > idx })
		prevSum := uint64(0)
		if i > 0 {
			prevSum = prefix[i-1]
		}
		offset := idx - prevSum
		ipUint := uint32(uint64(ranges[i].first) + offset)
		result = append(result, u32ToStr(ipUint))
	}

	// shuffle to break CIDR ordering
	rng.Shuffle(len(result), func(i, j int) { result[i], result[j] = result[j], result[i] })

	return result, nil
}
