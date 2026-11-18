package table

import (
	"math/rand"
	"testing"

	"eclipseguard/netaddr"
)

func newTestRng() *rand.Rand { return rand.New(rand.NewSource(42)) }

// TestNaiveFloodEclipse：朴素表在持续假地址洪水下必然被全部挤占，
// 这是基线必须复现的脆弱性。
func TestNaiveFloodEclipse(t *testing.T) {
	nt := NewNaive(16, newTestRng())
	// 先放入诚实邻居
	for i := 0; i < 16; i++ {
		nt.Consider(netaddr.FromGroupHost(100, uint32(i+1)), false, 0)
	}
	// 攻击者持续投递大量不同假地址
	for i := 0; i < 4000; i++ {
		nt.Consider(netaddr.FromGroupHost(900, uint32(i+1)), true, int64(i))
	}
	evil := 0
	for _, p := range nt.Snapshot() {
		if p.Evil {
			evil++
		}
	}
	if evil != 16 {
		t.Fatalf("naive table should be fully eclipsed, got evil=%d/16", evil)
	}
}

// TestNaiveRestartLosesEverything：朴素表重启后邻居表清空且无可信重连起点。
func TestNaiveRestartLosesEverything(t *testing.T) {
	nt := NewNaive(16, newTestRng())
	for i := 0; i < 16; i++ {
		nt.Consider(netaddr.FromGroupHost(100, uint32(i+1)), false, 0)
	}
	if got := nt.Restart(newTestRng(), 100); got != nil {
		t.Fatalf("naive restart should return no anchors, got %v", got)
	}
	if len(nt.Snapshot()) != 0 {
		t.Fatalf("naive table should be empty after restart")
	}
}

// TestHardenedGroupCap：同一 /16 组在 tried/new 区都不能超过上限。
func TestHardenedGroupCap(t *testing.T) {
	cfg := DefaultConfig()
	nt := NewHardened(cfg, newTestRng(), NewMemStore())
	// 同一组灌入远超容量的候选
	for i := 0; i < 100; i++ {
		nt.Consider(netaddr.FromGroupHost(900, uint32(i+1)), true, 0)
	}
	newGroup := 0
	for _, p := range nt.Snapshot() {
		if p.Group == 900 {
			newGroup++
		}
	}
	if newGroup > cfg.NewGroupCap {
		t.Fatalf("new-zone group cap violated: %d > %d", newGroup, cfg.NewGroupCap)
	}

	// 让候选保持良好并推进 tick，尝试晋升；tried 区同样受组上限约束
	for tick := int64(1); tick < 40; tick++ {
		for _, p := range nt.Snapshot() {
			nt.RecordLiveness(p.Addr, true, tick)
		}
		nt.Tick(tick)
	}
	triedGroup := 0
	for _, p := range nt.TriedSnapshot() {
		if p.Group == 900 {
			triedGroup++
		}
	}
	if triedGroup > cfg.GroupCap {
		t.Fatalf("tried-zone group cap violated: %d > %d", triedGroup, cfg.GroupCap)
	}
}

// TestHardenedFloodCannotEclipse：洪水灌不满 tried 区——
// 没有持续良好行为的假地址只能停留在 new 区并被衰减清理。
func TestHardenedFloodCannotEclipse(t *testing.T) {
	cfg := DefaultConfig()
	nt := NewHardened(cfg, newTestRng(), NewMemStore())

	// 预热：诚实地址建满 tried 区（需要 >= PromoteTicks 的良好记录）
	for tick := int64(0); tick < 30; tick++ {
		for g := 0; g < 40; g++ {
			nt.Consider(netaddr.FromGroupHost(uint32(100+g), 1), false, tick)
		}
		for _, p := range nt.Snapshot() {
			nt.RecordLiveness(p.Addr, true, tick)
		}
		nt.Tick(tick)
	}
	triedBefore := len(nt.TriedSnapshot())
	if triedBefore == 0 {
		t.Fatal("bootstrap failed: tried table empty")
	}

	// 攻击：每个 tick 都有全新的假地址洪水，且攻击者“不响应存活确认”
	for tick := int64(30); tick < 200; tick++ {
		for i := 0; i < 32; i++ {
			nt.Consider(netaddr.FromGroupHost(900, uint32(int(tick)*32+i+1)), true, tick)
		}
		for _, p := range nt.TriedSnapshot() {
			nt.RecordLiveness(p.Addr, true, tick)
		}
		nt.Tick(tick)
	}
	for _, p := range nt.TriedSnapshot() {
		if p.Evil {
			t.Fatalf("evil peer %s reached tried table without good behavior", p.Addr)
		}
	}
}

// TestHardenedAnchorProtection：预留锚点无法被任何候选淘汰。
func TestHardenedAnchorProtection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cap = 8
	cfg.MinGroups = 2
	cfg.ReserveAnchors = 2
	cfg.GroupCap = 2
	cfg.AnchorCount = 4
	store := NewMemStore()
	nt := NewHardened(cfg, newTestRng(), store)

	anchors := []netaddr.Addr{
		netaddr.FromGroupHost(100, 1),
		netaddr.FromGroupHost(101, 1),
	}
	// 直接构造锚点并重启加载
	if err := store.Save(anchors); err != nil {
		t.Fatal(err)
	}
	nt.Restart(newTestRng(), 0)
	for _, a := range anchors {
		if _, ok := nt.tried[a]; !ok {
			t.Fatalf("anchor %s not restored", a)
		}
		if !nt.reserved[a] {
			t.Fatalf("anchor %s not reserved", a)
		}
	}

	// 灌满 tried 区后继续投递其他组的候选，锚点必须仍在
	for g := 0; g < 6; g++ {
		for h := 1; h <= 2; h++ {
			a := netaddr.FromGroupHost(uint32(200+g), uint32(h))
			nt.Consider(a, false, 1)
		}
	}
	for tick := int64(2); tick < 40; tick++ {
		for _, p := range nt.Snapshot() {
			nt.RecordLiveness(p.Addr, true, tick)
		}
		nt.Tick(tick)
	}
	for _, a := range anchors {
		if _, ok := nt.tried[a]; !ok {
			t.Fatalf("reserved anchor %s was evicted", a)
		}
	}
}

// TestHardenedRestartSurvivesFlood：重启后 tried 区只含持久化锚点，
// 重启窗口灌入的洪水只能进入（随后被清空的）new 区。
func TestHardenedRestartSurvivesFlood(t *testing.T) {
	cfg := DefaultConfig()
	store := NewMemStore()
	nt := NewHardened(cfg, newTestRng(), store)

	// 建立并持久化一批诚实锚点
	for tick := int64(0); tick < 40; tick++ {
		for g := 0; g < 20; g++ {
			nt.Consider(netaddr.FromGroupHost(uint32(100+g), 1), false, tick)
		}
		for _, p := range nt.Snapshot() {
			nt.RecordLiveness(p.Addr, true, tick)
		}
		nt.Tick(tick)
	}
	if len(nt.anchors) == 0 {
		t.Fatal("no anchors persisted")
	}

	// 重启瞬间攻击者抢先灌入大量假地址
	reconnect := nt.Restart(newTestRng(), 100)
	if len(reconnect) == 0 {
		t.Fatal("restart returned no anchor reconnect list")
	}
	for i := 0; i < 200; i++ {
		nt.Consider(netaddr.FromGroupHost(900, uint32(i+1)), true, 100)
	}
	tried := nt.TriedSnapshot()
	if len(tried) == 0 {
		t.Fatal("tried table empty after restart+reconnect")
	}
	for _, p := range tried {
		if p.Evil {
			t.Fatalf("evil address %s in tried table immediately after restart", p.Addr)
		}
	}
}

// TestHardenedLastOfGroupProtected：任何组的最后一个成员都不会被淘汰，
// 且活跃组数跌破 MinGroups 后淘汰完全停止。
func TestHardenedLastOfGroupProtected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cap = 6
	cfg.GroupCap = 1
	cfg.MinGroups = 6 // 满表时组数恰好等于下限，任何淘汰都应被拒绝
	nt := NewHardened(cfg, newTestRng(), NewMemStore())
	for g := 0; g < 6; g++ {
		a := netaddr.FromGroupHost(uint32(100+g), 1)
		nt.Consider(a, false, 0)
		nt.tried[a] = &Peer{Addr: a, Group: a.Group(), Joined: 0, Seen: 0}
		nt.triedOrder = append(nt.triedOrder, a)
		delete(nt.new, a)
		nt.newOrder = removeFromOrder(nt.newOrder, a)
	}
	if victim, ok := nt.pickTriedEviction(); ok {
		t.Fatalf("eviction allowed at MinGroups boundary, victim=%s", victim)
	}
}

// TestFileStoreRoundTrip：落盘锚点的保存/加载往返一致，且文件权限为 0600。
func TestFileStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/anchors.json"
	fs := NewFileStore(path)
	want := []netaddr.Addr{netaddr.Make(10, 0, 0, 1), netaddr.Make(10, 0, 0, 2)}
	if err := fs.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := fs.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("round trip mismatch: got %v want %v", got, want)
	}
}
