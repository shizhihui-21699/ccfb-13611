// Package sim 实现上千节点规模的 P2P 网络仿真：诚实节点、攻击者节点、
// 节点上下线（churn）、邻居发现抽样与攻击者地址洪水，并驱动两种邻居表
// 策略在完全相同的网络条件下对比。
package sim

import (
	"math/rand"

	"eclipseguard/netaddr"
)

const (
	honestGroupBase = 100 // 诚实节点 /16 组号起点
	evilGroupBase   = 900 // 攻击者 /16 组号起点，与诚实节点组空间不相交
)

// World 是一个仿真网络实例：地址池、分组与在线状态。
type World struct {
	rng *rand.Rand

	Honest []netaddr.Addr
	Evil   []netaddr.Addr

	honestByGroup map[uint32][]netaddr.Addr
	evilByGroup   map[uint32][]netaddr.Addr

	live map[netaddr.Addr]bool
}

// NewWorld 构造网络。honestGroups/evilGroups 分别控制两类节点占据的 /16
// 组数量：攻击者组越少越“集中”（模拟同一机房批量开假节点），组越多越
// “分散”。主机号在组内轮询分配。
func NewWorld(rng *rand.Rand, honestN, evilN, honestGroups, evilGroups int) *World {
	w := &World{
		rng:           rng,
		honestByGroup: map[uint32][]netaddr.Addr{},
		evilByGroup:   map[uint32][]netaddr.Addr{},
		live:          map[netaddr.Addr]bool{},
	}
	for i := 0; i < honestN; i++ {
		g := uint32(honestGroupBase + i%honestGroups)
		host := uint32(i/honestGroups) + 1
		a := netaddr.FromGroupHost(g, host)
		w.Honest = append(w.Honest, a)
		w.honestByGroup[g] = append(w.honestByGroup[g], a)
		w.live[a] = true
	}
	for i := 0; i < evilN; i++ {
		g := uint32(evilGroupBase + i%evilGroups)
		host := uint32(i/evilGroups) + 1
		a := netaddr.FromGroupHost(g, host)
		w.Evil = append(w.Evil, a)
		w.evilByGroup[g] = append(w.evilByGroup[g], a)
		// 攻击者节点始终在线——这是攻击者相对真实网络的固有优势。
		w.live[a] = true
	}
	return w
}

// IsLive 返回地址当前是否在线。
func (w *World) IsLive(a netaddr.Addr) bool { return w.live[a] }

// LiveHonestGroups 返回当前仍有在线成员的诚实节点组。
func (w *World) LiveHonestGroups() []uint32 {
	var out []uint32
	for g, addrs := range w.honestByGroup {
		for _, a := range addrs {
			if w.live[a] {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// SampleHonest 从在线诚实节点中均匀随机抽 n 个不重复地址。
// 朴素实现的“发现”使用该方式：只保证地址来自诚实池，但不保证组多样性。
func (w *World) SampleHonest(n int) []netaddr.Addr {
	var pool []netaddr.Addr
	for _, a := range w.Honest {
		if w.live[a] {
			pool = append(pool, a)
		}
	}
	shuffleCopy(w.rng, pool)
	if len(pool) > n {
		pool = pool[:n]
	}
	return pool
}

// SampleHonestStratified 是加固实现使用的分层随机发现：先随机选 n 个不同
// 的在线 /16 组，再从每组各取一个成员。即使攻击者占了全网多数地址，
// 自己发现的候选仍然在诚实地址空间内且天然具备组多样性。
func (w *World) SampleHonestStratified(n int) []netaddr.Addr {
	groups := w.LiveHonestGroups()
	shuffleCopy(w.rng, groups)
	out := make([]netaddr.Addr, 0, n)
	for _, g := range groups {
		if len(out) >= n {
			break
		}
		var live []netaddr.Addr
		for _, a := range w.honestByGroup[g] {
			if w.live[a] {
				live = append(live, a)
			}
		}
		if len(live) == 0 {
			continue
		}
		out = append(out, live[w.rng.Intn(len(live))])
	}
	return out
}

// SampleEvil 模拟攻击者的地址洪水：从其地址池随机投递 n 个不重复假地址。
func (w *World) SampleEvil(n int) []netaddr.Addr {
	pool := append([]netaddr.Addr(nil), w.Evil...)
	shuffleCopy(w.rng, pool)
	if len(pool) > n {
		pool = pool[:n]
	}
	return pool
}

// Churn 推进一个周期的节点上下线：在线节点以 leaveP 概率离开，离线节点
// 以 returnP 概率回归。攻击者节点不参与 churn。
func (w *World) Churn(leaveP, returnP float64) {
	for _, a := range w.Honest {
		if w.live[a] {
			if w.rng.Float64() < leaveP {
				w.live[a] = false
			}
			continue
		}
		if w.rng.Float64() < returnP {
			w.live[a] = true
		}
	}
}

func shuffleCopy[T any](rng *rand.Rand, s []T) {
	rng.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
}
