package table

import (
	"math/rand"

	"eclipseguard/netaddr"
)

// NaiveTable 模拟改造前的常见实现：
//
//   - 单一固定大小邻居表，候选来源不做区分（自己发现的与对端投递的一视同仁）；
//   - 表满时随机淘汰一个条目，老邻居没有任何特殊保护；
//   - 不做网段多样性限制，同一 /16 的假地址可以占满全表；
//   - 重启后邻居表与锚点全部丢失，只能靠外部投递的候选重新填表——
//     攻击者在重启窗口持续灌水即可几乎确定性地完成包围。
type NaiveTable struct {
	cap     int
	rng     *rand.Rand
	peers   map[netaddr.Addr]*Peer
	addrs   []netaddr.Addr // 保持稳定遍历顺序
	anchors []netaddr.Addr
}

// NewNaive 创建朴素邻居表。groupCap 仅用于接口对称，naive 不做组限制（传 0）。
func NewNaive(capacity int, rng *rand.Rand) *NaiveTable {
	return &NaiveTable{
		cap:   capacity,
		rng:   rng,
		peers: make(map[netaddr.Addr]*Peer),
	}
}

func (t *NaiveTable) Name() string { return "naive" }

func (t *NaiveTable) Consider(addr netaddr.Addr, evil bool, now int64) Decision {
	if _, ok := t.peers[addr]; ok {
		return DecDup
	}
	p := &Peer{Addr: addr, Evil: evil, Group: addr.Group(), Joined: now, Seen: now}
	if len(t.addrs) < t.cap {
		t.peers[addr] = p
		t.addrs = append(t.addrs, addr)
		return DecAccepted
	}
	// 随机淘汰：攻击者持续投递假地址时，每个真实邻居被逐步挤出只是时间问题。
	idx := t.rng.Intn(len(t.addrs))
	victim := t.addrs[idx]
	delete(t.peers, victim)
	t.addrs[idx] = addr
	t.peers[addr] = p
	return DecEvicted
}

func (t *NaiveTable) RecordLiveness(addr netaddr.Addr, good bool, now int64) {
	if p, ok := t.peers[addr]; ok {
		p.Seen = now
		if good {
			p.GoodTicks++
		}
	}
}

func (t *NaiveTable) Tick(now int64) {
	// 朴素表没有观察期/晋升机制，每个 tick 无额外工作。
}

func (t *NaiveTable) Snapshot() []Peer {
	out := make([]Peer, 0, len(t.addrs))
	for _, a := range t.addrs {
		if p, ok := t.peers[a]; ok {
			out = append(out, *p)
		}
	}
	return out
}

func (t *NaiveTable) Remove(addr netaddr.Addr) {
	if _, ok := t.peers[addr]; !ok {
		return
	}
	delete(t.peers, addr)
	for i, a := range t.addrs {
		if a == addr {
			t.addrs = append(t.addrs[:i], t.addrs[i+1:]...)
			break
		}
	}
}

// Restart 对朴素表意味着邻居表清零；锚点虽然存在但重启后不主动重连，
// 真实系统里等价于 anchors.dat 缺失/未使用。返回 nil 表示没有可信起点。
func (t *NaiveTable) Restart(_ UintReader, _ int64) []netaddr.Addr {
	t.peers = make(map[netaddr.Addr]*Peer)
	t.addrs = nil
	t.anchors = nil
	return nil
}

func (t *NaiveTable) Reanchor(addr netaddr.Addr, _ int64) bool {
	// 朴素实现不维护锚点。
	return false
}
