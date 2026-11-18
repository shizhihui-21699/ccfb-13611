package sim

import (
	"math/rand"

	"eclipseguard/netaddr"
	"eclipseguard/table"
)

// Strategy 选择邻居表实现。
type Strategy string

const (
	StratNaive    Strategy = "naive"
	StratHardened Strategy = "hardened"
)

// Config 描述一次独立试验（trial）的全部参数。
type Config struct {
	Strategy Strategy

	HonestN      int     // 诚实节点总数
	EvilN        int     // 攻击者地址总数
	HonestGroups int     // 诚实节点占用的 /16 组数
	EvilGroups   int     // 攻击者占用的 /16 组数（越小越集中）
	Bootstrap    int     // 无攻击预热 tick 数
	AttackTicks  int     // 攻击阶段 tick 数
	RestartTick  int     // 攻击阶段内的重启 tick（<0 表示不重启）
	RestartGrace int     // 重启宽限期 tick 数：期内诚实邻居尚未回应，只有攻击者洪水到达
	LeaveP       float64 // 诚实节点每 tick 下线概率
	ReturnP      float64 // 离线诚实节点每 tick 回归概率
	DiscoverPer  int     // 每 tick 主动发现的候选数
	FloodPer     int     // 攻击者每 tick 投递的假地址数
	Seed         int64
}

// DefaultConfig 返回标准试验配置（约 1000 诚实节点）。
func DefaultConfig(strat Strategy, evilN, evilGroups int) Config {
	return Config{
		Strategy:     strat,
		HonestN:      1000,
		EvilN:        evilN,
		HonestGroups: 40,
		EvilGroups:   evilGroups,
		Bootstrap:    60,
		AttackTicks:  250,
		RestartTick:  120,
		RestartGrace: 3,
		LeaveP:       1.0 / 120.0,
		ReturnP:      1.0 / 30.0,
		DiscoverPer:  4,
		FloodPer:     16,
	}
}

// Snapshot 是单个 tick 上目标节点邻居表的测量值。
type Snapshot struct {
	Tick          int
	ActiveCap     int
	ActiveN       int
	EvilN         int
	EvilRatio     float64
	Distinct      int
	MaxGroupN     int // 单个 /16 组在活跃邻居中的最大条目数
	MaxGroupRatio float64
	FullCap       int
	FullN         int
	FullEvil      int
}

// TrialResult 汇总一次试验的结果。
type TrialResult struct {
	Cfg Config

	// 攻击窗口内是否发生过各档“包围”。
	EclipsedFull  bool // 全部活跃邻居都是攻击者
	EclipsedMajor bool // 攻击者占比 >= 75%
	EclipsedHalf  bool // 攻击者占比 >= 50%

	// 重启后首个 tick 的攻击者占比（衡量重启窗口的针对性攻击效果）。
	PostRestartEvilRatio float64
	PostRestartFull      bool
	PostRestartMajor     bool

	// 最终与窗口内最大攻击者占比。
	FinalEvilRatio float64
	MaxEvilRatio   float64
	MeanEvilRatio  float64

	// 窗口内单个 /16 组在活跃邻居中的最大占比：衡量组多样性防线的实际效果。
	MaxGroupRatio float64

	// 稳态下活跃邻居的平均数量（验证抗攻击设计没有牺牲网络可用性）。
	MeanActiveN float64

	Snapshots []Snapshot
}

// RunTrial 在独立 RNG 与独立网络上执行一次试验。
func RunTrial(cfg Config) TrialResult {
	rng := rand.New(rand.NewSource(cfg.Seed))
	world := NewWorld(rng, cfg.HonestN, cfg.EvilN, cfg.HonestGroups, cfg.EvilGroups)

	store := table.NewMemStore()
	var nt table.NeighborTable
	tcfg := table.DefaultConfig()
	switch cfg.Strategy {
	case StratHardened:
		nt = table.NewHardened(tcfg, rng, store)
	default:
		nt = table.NewNaive(tcfg.Cap, rng)
	}

	res := TrialResult{Cfg: cfg}
	totalTicks := cfg.Bootstrap + cfg.AttackTicks
	restartDone := false
	postRestartRecorded := false
	graceLeft := 0 // >0 表示处于重启宽限期：诚实发现暂停，仅攻击者洪水可达
	ratioSum, activeSum, ratioSamples := 0.0, 0, 0

	// ---- 预热：无攻击者，仅靠主动发现建表 ----
	bootstrapFill(nt, world, rng, cfg)

	for tick := 0; tick < totalTicks; tick++ {
		inAttack := tick >= cfg.Bootstrap
		attackTick := tick - cfg.Bootstrap

		// 1. 网络抖动 + 清理已下线邻居
		world.Churn(cfg.LeaveP, cfg.ReturnP)
		removeDead(nt, world)

		// 2. 攻击阶段内的计划重启
		if inAttack && !restartDone && cfg.RestartTick >= 0 && attackTick == cfg.RestartTick {
			reconnect := nt.Restart(rng, int64(tick))
			// 加固表：优先重连持久化锚点，成功者升级为新锚点。
			for _, a := range reconnect {
				if world.IsLive(a) {
					nt.Consider(a, false, int64(tick))
					nt.RecordLiveness(a, true, int64(tick))
					nt.Reanchor(a, int64(tick))
				}
			}
			restartDone = true
			graceLeft = cfg.RestartGrace
		}

		// 3. 存活确认（在线即确认；攻击者节点恒在线）
		for _, p := range nt.Snapshot() {
			nt.RecordLiveness(p.Addr, world.IsLive(p.Addr), int64(tick))
		}

		// 4. 主动发现：加固表用分层随机抽样，朴素表用普通均匀抽样。
		//    重启宽限期内旧邻居尚未回应、新发现无法建立，模拟真实攻击中
		//    “节点重启后只有抢先响应的攻击者可达”的时间差。
		if graceLeft == 0 {
			var found []netaddr.Addr
			if cfg.Strategy == StratHardened {
				found = world.SampleHonestStratified(cfg.DiscoverPer)
			} else {
				found = world.SampleHonest(cfg.DiscoverPer)
			}
			for _, a := range found {
				nt.Consider(a, false, int64(tick))
			}
		} else {
			graceLeft--
		}

		// 5. 攻击者地址洪水（仅攻击阶段）
		if inAttack {
			for _, a := range world.SampleEvil(cfg.FloodPer) {
				nt.Consider(a, true, int64(tick))
			}
		}

		// 6. 表内周期逻辑（观察期衰减、晋升、锚点刷新）
		nt.Tick(int64(tick))

		// 7. 测量（仅攻击窗口计入统计）
		if inAttack {
			snap := measure(nt, tcfg, attackTick)
			res.Snapshots = append(res.Snapshots, snap)
			ratioSum += snap.EvilRatio
			activeSum += snap.ActiveN
			ratioSamples++
			if snap.EvilRatio > res.MaxEvilRatio {
				res.MaxEvilRatio = snap.EvilRatio
			}
			if snap.MaxGroupRatio > res.MaxGroupRatio {
				res.MaxGroupRatio = snap.MaxGroupRatio
			}
			if snap.EvilRatio >= 1.0 && snap.ActiveN > 0 {
				res.EclipsedFull = true
			}
			if snap.EvilRatio >= 0.75 && snap.ActiveN > 0 {
				res.EclipsedMajor = true
			}
			if snap.EvilRatio >= 0.5 && snap.ActiveN > 0 {
				res.EclipsedHalf = true
			}
			if restartDone && !postRestartRecorded {
				// 重启完成后的第一个测量帧：衡量重启窗口攻击的针对性效果。
				res.PostRestartEvilRatio = snap.EvilRatio
				res.PostRestartFull = snap.ActiveN > 0 && snap.EvilRatio >= 1.0
				res.PostRestartMajor = snap.EvilRatio >= 0.75
				postRestartRecorded = true
			}
		}
	}

	if n := len(res.Snapshots); n > 0 {
		last := res.Snapshots[n-1]
		res.FinalEvilRatio = last.EvilRatio
		res.MeanEvilRatio = ratioSum / float64(ratioSamples)
		res.MeanActiveN = float64(activeSum) / float64(ratioSamples)
	}
	return res
}

// bootstrapFill 在无攻击条件下填充邻居表：分层抽样 + 完整 tick 推进，
// 让加固表的观察期候选有时间晋升、锚点有时间建立。
func bootstrapFill(nt table.NeighborTable, world *World, rng *rand.Rand, cfg Config) {
	for tick := 0; tick < cfg.Bootstrap; tick++ {
		world.Churn(cfg.LeaveP, cfg.ReturnP)
		removeDead(nt, world)
		for _, p := range nt.Snapshot() {
			nt.RecordLiveness(p.Addr, world.IsLive(p.Addr), int64(tick))
		}
		var found []netaddr.Addr
		if cfg.Strategy == StratHardened {
			found = world.SampleHonestStratified(cfg.DiscoverPer * 2)
		} else {
			found = world.SampleHonest(cfg.DiscoverPer * 2)
		}
		for _, a := range found {
			nt.Consider(a, false, int64(tick))
		}
		nt.Tick(int64(tick))
	}
}

func removeDead(nt table.NeighborTable, world *World) {
	for _, p := range nt.Snapshot() {
		if !world.IsLive(p.Addr) {
			nt.Remove(p.Addr)
		}
	}
}

// activePeers 返回用于统计的“活跃邻居”视图：加固表只统计 tried 区，
// 朴素表的整个表即活跃表。
func activePeers(nt table.NeighborTable, tcfg table.Config) []table.Peer {
	if h, ok := nt.(*table.HardenedTable); ok {
		return h.TriedSnapshot()
	}
	_ = tcfg
	return nt.Snapshot()
}

func measure(nt table.NeighborTable, tcfg table.Config, attackTick int) Snapshot {
	active := activePeers(nt, tcfg)
	full := nt.Snapshot()

	snap := Snapshot{Tick: attackTick, ActiveCap: tcfg.Cap, FullCap: tcfg.Cap + tcfg.NewCap}
	groups := map[uint32]int{}
	for _, p := range active {
		snap.ActiveN++
		if p.Evil {
			snap.EvilN++
		}
		groups[p.Group]++
	}
	for _, gN := range groups {
		if gN > snap.MaxGroupN {
			snap.MaxGroupN = gN
		}
	}
	for _, p := range full {
		snap.FullN++
		if p.Evil {
			snap.FullEvil++
		}
	}
	snap.Distinct = len(groups)
	if snap.ActiveN > 0 {
		snap.EvilRatio = float64(snap.EvilN) / float64(snap.ActiveN)
		snap.MaxGroupRatio = float64(snap.MaxGroupN) / float64(snap.ActiveN)
	}
	return snap
}
