// Package table 实现邻居发现与邻居表管理的两种策略：
//
//   - NaiveTable：改造前的朴素实现（固定单表 + 随机替换 + 重启清空），
//     攻击者只要持续投递假地址就有机会逐步挤占全部槽位。
//   - HardenedTable：改造后的加固实现（tried/new 双表、组多样性上限、
//     信任锚点、观察期晋升、重启持久化），让“控制大量地址”难以转化为
//     “包围某个节点”。
package table

import "eclipseguard/netaddr"

// Peer 是邻居表里的一条记录。
type Peer struct {
	Addr   netaddr.Addr
	Evil   bool // 是否为攻击者节点
	Group  uint32
	Joined int64 // 进入邻居表的 tick（用于观察期与统计）

	// 仅 HardenedTable 使用：
	Probation bool  // 是否处于观察期（new 区）
	Seen      int64 // 最近一次确认存活的 tick
	GoodTicks int64 // 累计存活/良好 tick 数
}

// Decision 描述一次候选投递（Consider）的处理结果，用于统计与测试断言。
type Decision int

const (
	// DecDup：候选已在表中，忽略。
	DecDup Decision = iota
	// DecAccepted：候选被接受（进入 new 区或直接占用空槽）。
	DecAccepted
	// DecGroupFull：候选所属组已达多样性上限，拒绝。
	DecGroupFull
	// DecRejected：表满且没有可淘汰对象，拒绝。
	DecRejected
	// DecEvicted：候选被接受，同时淘汰了一个旧条目。
	DecEvicted
	// DecAnchorProtected：本可淘汰，但唯一可淘汰对象是信任锚点，拒绝。
	DecAnchorProtected
)

func (d Decision) String() string {
	switch d {
	case DecDup:
		return "dup"
	case DecAccepted:
		return "accepted"
	case DecGroupFull:
		return "group-full"
	case DecEvicted:
		return "evicted"
	case DecAnchorProtected:
		return "anchor-protected"
	default:
		return "rejected"
	}
}

// Config 是加固表的策略参数（naive 表只使用 Cap 与 GroupCap）。
type Config struct {
	Cap            int   // 活跃邻居表总容量（tried 区上限）
	NewCap         int   // new（观察期）区容量
	GroupCap       int   // tried 区每个 /16 组的最大条目数
	NewGroupCap    int   // new 区每个 /16 组的最大条目数
	PromoteTicks   int64 // 观察期需要连续保持良好的 tick 数
	AnchorCount    int   // 持久化信任锚点数量
	MinGroups      int   // tried 区期望维持的最小组数量（淘汰时保护多样性）
	ReserveAnchors int   // 始终预留、绝不淘汰的锚点槽位数
}

// DefaultConfig 返回仿真使用的默认加固参数。
func DefaultConfig() Config {
	return Config{
		Cap:            32,
		NewCap:         32,
		GroupCap:       4,
		NewGroupCap:    4,
		PromoteTicks:   8,
		AnchorCount:    16,
		ReserveAnchors: 4,
		MinGroups:      6,
	}
}

// NeighborTable 是两种策略共同实现的接口，仿真引擎只依赖该接口。
type NeighborTable interface {
	// Consider 处理一个被发现/被投递的候选地址。
	Consider(addr netaddr.Addr, evil bool, now int64) Decision
	// RecordLiveness 上报某邻居本轮存活确认（good=true 表示行为正常）。
	RecordLiveness(addr netaddr.Addr, good bool, now int64)
	// Tick 推进一个仿真周期，处理晋升、老化等内部逻辑。
	Tick(now int64)
	// Snapshot 返回当前全部邻居副本。
	Snapshot() []Peer
	// Remove 在节点下线时移除邻居。
	Remove(addr netaddr.Addr)
	// Restart 模拟节点重启，rng 用于重连顺序随机化，返回重连的锚点地址。
	Restart(rng UintReader, now int64) []netaddr.Addr
	// Reanchor 把一个已确认存活的地址升级为信任锚点。
	Reanchor(addr netaddr.Addr, now int64) bool
	// Name 返回策略名。
	Name() string
}

// UintReader 抽象随机数来源，便于测试注入确定性 RNG。
type UintReader interface {
	Intn(n int) int
}
