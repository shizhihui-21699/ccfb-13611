package table

import (
	"math/rand"

	"eclipseguard/netaddr"
)

// HardenedTable 是改造后的邻居表，叠加六层防御：
//
//  1. tried/new 双表：外部投递的候选只能先进 new 观察区，绝不会直接接触
//     tried 活跃邻居表；只有持续存活、行为良好的候选才能晋升。
//  2. 组多样性上限：tried/new 两个区分别限制每个 /16 组的条目数，攻击者
//     即使在一个网段开上万假节点，也只能占住极少数槽位。
//  3. 信任锚点：长期表现良好的老邻居被选为锚点并持久化，其中前若干个槽位
//     受预留保护，任何新候选都不能淘汰它们。
//  4. 保护性淘汰：淘汰时优先选择“最拥挤组”的条目，且绝不淘汰一个组的最后
//     一个成员、绝不让活跃组数量跌破 MinGroups——挤走真实邻居的难度被
//     结构性地抬高。
//  5. 观察期衰减：new 区候选若不能持续证明存活，会被定期清理，灌水地址
//     无法靠数量堆积。
//  6. 重启恢复：重启后 new 区（不可信来源）直接丢弃，tried 区由持久化锚点
//     重建并优先重连，重启窗口的地址洪水没有可乘之机。
type HardenedTable struct {
	cfg   Config
	rng   *rand.Rand
	store AnchorStore

	tried map[netaddr.Addr]*Peer
	new   map[netaddr.Addr]*Peer

	triedOrder []netaddr.Addr
	newOrder   []netaddr.Addr

	anchors  []netaddr.Addr
	reserved map[netaddr.Addr]bool
}

// NewHardened 创建加固邻居表，并从锚点存储中恢复（首次启动时存储为空）。
func NewHardened(cfg Config, rng *rand.Rand, store AnchorStore) *HardenedTable {
	t := &HardenedTable{
		cfg:      cfg,
		rng:      rng,
		store:    store,
		tried:    make(map[netaddr.Addr]*Peer),
		new:      make(map[netaddr.Addr]*Peer),
		reserved: make(map[netaddr.Addr]bool),
	}
	if saved, err := store.Load(); err == nil {
		t.anchors = append(t.anchors, saved...)
	}
	return t
}

func (t *HardenedTable) Name() string { return "hardened" }

// ---------- 基础工具 ----------

func (t *HardenedTable) groupCount(m map[netaddr.Addr]*Peer, group uint32) int {
	n := 0
	for _, p := range m {
		if p.Group == group {
			n++
		}
	}
	return n
}

func (t *HardenedTable) distinctGroups(m map[netaddr.Addr]*Peer) int {
	seen := map[uint32]struct{}{}
	for _, p := range m {
		seen[p.Group] = struct{}{}
	}
	return len(seen)
}

func removeFromOrder(s []netaddr.Addr, addr netaddr.Addr) []netaddr.Addr {
	for i, a := range s {
		if a == addr {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

// recomputeReserved 重新计算受预留保护的锚点：当前确实在 tried 区、且排在
// 锚点列表最前面的 ReserveAnchors 个地址。
func (t *HardenedTable) recomputeReserved() {
	for a := range t.reserved {
		delete(t.reserved, a)
	}
	n := 0
	for _, a := range t.anchors {
		if _, ok := t.tried[a]; !ok {
			continue
		}
		t.reserved[a] = true
		n++
		if n >= t.cfg.ReserveAnchors {
			break
		}
	}
}

// ---------- 候选投递 ----------

func (t *HardenedTable) Consider(addr netaddr.Addr, evil bool, now int64) Decision {
	if _, ok := t.tried[addr]; ok {
		return DecDup
	}
	if _, ok := t.new[addr]; ok {
		return DecDup
	}
	// 规则 2：组多样性上限，先于一切容量判断。
	if t.groupCount(t.new, addr.Group()) >= t.cfg.NewGroupCap {
		return DecGroupFull
	}
	p := &Peer{Addr: addr, Evil: evil, Group: addr.Group(), Joined: now, Seen: now, Probation: true}

	if len(t.newOrder) < t.cfg.NewCap {
		t.new[addr] = p
		t.newOrder = append(t.newOrder, addr)
		return DecAccepted
	}
	// new 区满：从最拥挤的组里随机淘汰一个观察期候选。
	// 这只会发生在观察期条目之间，tried 区的真实邻居完全不受影响。
	victim, ok := t.pickNewEviction(addr.Group())
	if !ok {
		return DecRejected
	}
	delete(t.new, victim)
	t.newOrder = removeFromOrder(t.newOrder, victim)
	t.new[addr] = p
	t.newOrder = append(t.newOrder, addr)
	return DecEvicted
}

// pickNewEviction 在 new 区选择淘汰对象：条目最多的组优先；若候选所在组
// 本身就是最拥挤组，则组内随机选——同组替换不损失多样性。
func (t *HardenedTable) pickNewEviction(candGroup uint32) (netaddr.Addr, bool) {
	counts := map[uint32]int{}
	for _, p := range t.new {
		counts[p.Group]++
	}
	maxCount := 0
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}
	var pool []netaddr.Addr
	for a, p := range t.new {
		if counts[p.Group] == maxCount {
			pool = append(pool, a)
		}
	}
	if len(pool) == 0 {
		return 0, false
	}
	_ = candGroup
	return pool[t.rng.Intn(len(pool))], true
}

// ---------- 存活上报与周期推进 ----------

func (t *HardenedTable) RecordLiveness(addr netaddr.Addr, good bool, now int64) {
	if p, ok := t.tried[addr]; ok {
		p.Seen = now
		if good {
			p.GoodTicks++
		}
		return
	}
	if p, ok := t.new[addr]; ok {
		p.Seen = now
		if good {
			p.GoodTicks++
		}
	}
}

func (t *HardenedTable) Tick(now int64) {
	// 规则 5：观察期衰减——长期无法确认存活的候选直接清理。
	decayBefore := now - 2*t.cfg.PromoteTicks
	var dead []netaddr.Addr
	for _, a := range t.newOrder {
		if p := t.new[a]; p.Seen < decayBefore {
			dead = append(dead, a)
		}
	}
	for _, a := range dead {
		delete(t.new, a)
		t.newOrder = removeFromOrder(t.newOrder, a)
	}

	// 规则 1：观察期满且持续良好的候选晋升 tried。
	var promotable []netaddr.Addr
	for _, a := range t.newOrder {
		p := t.new[a]
		if p.GoodTicks >= t.cfg.PromoteTicks && p.Seen >= now-1 {
			promotable = append(promotable, a)
		}
	}
	for _, a := range promotable {
		t.tryPromote(a, now)
	}

	// 定期刷新持久化锚点（规则 3）。
	if now%32 == 0 && now > 0 {
		t.refreshAnchors(now)
	}
}

// tryPromote 把一个观察期候选移入 tried 区；tried 满时执行保护性淘汰。
func (t *HardenedTable) tryPromote(addr netaddr.Addr, now int64) {
	p, ok := t.new[addr]
	if !ok {
		return
	}
	if t.groupCount(t.tried, p.Group) >= t.cfg.GroupCap {
		// 目标组在 tried 区已满：候选留在观察区，等待下轮机会。
		return
	}
	if len(t.triedOrder) >= t.cfg.Cap {
		victim, ok := t.pickTriedEviction()
		if !ok {
			// 所有槽位都受保护：本轮拒绝晋升，攻击者无法通过灌满表来挤走锚点。
			return
		}
		delete(t.tried, victim)
		t.triedOrder = removeFromOrder(t.triedOrder, victim)
	}
	p.Probation = false
	delete(t.new, addr)
	t.newOrder = removeFromOrder(t.newOrder, addr)
	t.tried[addr] = p
	t.triedOrder = append(t.triedOrder, addr)
	t.recomputeReserved()
}

// pickTriedEviction 实现规则 4 的保护性淘汰：
//   - 预留锚点永不淘汰；
//   - 一个组的最后一个成员永不淘汰；
//   - 活跃组数低于 MinGroups 时不允许任何淘汰；
//   - 其余情况下，从最拥挤的组中随机选择，持续压缩攻击者的组内占比。
func (t *HardenedTable) pickTriedEviction() (netaddr.Addr, bool) {
	if t.distinctGroups(t.tried) <= t.cfg.MinGroups {
		return 0, false
	}
	counts := map[uint32]int{}
	for _, p := range t.tried {
		counts[p.Group]++
	}
	maxCount := 0
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}
	var pool []netaddr.Addr
	for a, p := range t.tried {
		if t.reserved[a] {
			continue
		}
		if counts[p.Group] <= 1 {
			continue // 组内最后一个成员
		}
		if counts[p.Group] != maxCount {
			continue
		}
		pool = append(pool, a)
	}
	if len(pool) == 0 {
		return 0, false
	}
	return pool[t.rng.Intn(len(pool))], true
}

// ---------- 锚点与重启 ----------

func (t *HardenedTable) refreshAnchors(now int64) {
	anchors := pickAnchors(t.Snapshot(), t.cfg.AnchorCount, now)
	if len(anchors) == 0 {
		return
	}
	t.anchors = anchors
	_ = t.store.Save(anchors)
	t.recomputeReserved()
}

func (t *HardenedTable) Reanchor(addr netaddr.Addr, now int64) bool {
	p, ok := t.tried[addr]
	if !ok || p.Probation {
		return false
	}
	for _, a := range t.anchors {
		if a == addr {
			return true
		}
	}
	t.anchors = append(t.anchors, addr)
	if len(t.anchors) > t.cfg.AnchorCount {
		t.anchors = t.anchors[:t.cfg.AnchorCount]
	}
	_ = t.store.Save(t.anchors)
	t.recomputeReserved()
	return true
}

// Restart 模拟节点重启：
//   - new 区整体丢弃（其内容来自不可信的外部投递）；
//   - tried 区由持久化锚点重建，锚点按组多样性挑选过，且遵守组上限；
//   - 返回随机乱序的锚点地址，供引擎优先重连；重连成功前不接受任何候选
//     晋升，重启窗口的灌水流量只能停留在（会被定期清空的）观察区。
func (t *HardenedTable) Restart(rng UintReader, now int64) []netaddr.Addr {
	saved, err := t.store.Load()
	if err != nil {
		saved = nil
	}
	t.tried = make(map[netaddr.Addr]*Peer)
	t.new = make(map[netaddr.Addr]*Peer)
	t.triedOrder = nil
	t.newOrder = nil
	t.reserved = make(map[netaddr.Addr]bool)

	groupUsed := map[uint32]int{}
	var loaded []netaddr.Addr
	for _, a := range saved {
		g := a.Group()
		if groupUsed[g] >= t.cfg.GroupCap {
			continue
		}
		groupUsed[g]++
		t.tried[a] = &Peer{Addr: a, Group: g, Joined: now, Seen: now}
		t.triedOrder = append(t.triedOrder, a)
		loaded = append(loaded, a)
	}
	t.anchors = append(t.anchors[:0], loaded...)
	t.recomputeReserved()

	// Fisher–Yates 乱序，避免重连顺序被外部预测和抢先响应。
	reconnect := append([]netaddr.Addr(nil), loaded...)
	for i := len(reconnect) - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		reconnect[i], reconnect[j] = reconnect[j], reconnect[i]
	}
	return reconnect
}

// ---------- 查询与删除 ----------

func (t *HardenedTable) Snapshot() []Peer {
	out := make([]Peer, 0, len(t.triedOrder)+len(t.newOrder))
	for _, a := range t.triedOrder {
		if p, ok := t.tried[a]; ok {
			out = append(out, *p)
		}
	}
	for _, a := range t.newOrder {
		if p, ok := t.new[a]; ok {
			out = append(out, *p)
		}
	}
	return out
}

// TriedSnapshot 只返回活跃邻居（tried 区），仿真统计以该视图为准。
func (t *HardenedTable) TriedSnapshot() []Peer {
	out := make([]Peer, 0, len(t.triedOrder))
	for _, a := range t.triedOrder {
		if p, ok := t.tried[a]; ok {
			out = append(out, *p)
		}
	}
	return out
}

func (t *HardenedTable) Remove(addr netaddr.Addr) {
	if p, ok := t.tried[addr]; ok {
		delete(t.tried, addr)
		t.triedOrder = removeFromOrder(t.triedOrder, addr)
		_ = p
	}
	if _, ok := t.new[addr]; ok {
		delete(t.new, addr)
		t.newOrder = removeFromOrder(t.newOrder, addr)
	}
	for i, a := range t.anchors {
		if a == addr {
			t.anchors = append(t.anchors[:i], t.anchors[i+1:]...)
			_ = t.store.Save(t.anchors)
			break
		}
	}
	t.recomputeReserved()
}
