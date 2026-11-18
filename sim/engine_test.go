package sim

import (
	"math/rand"
	"testing"

	"eclipseguard/table"
)

// TestStratifiedSamplingDiversity：分层抽样返回的候选必须来自不同的 /16 组。
func TestStratifiedSamplingDiversity(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	w := NewWorld(rng, 1000, 500, 40, 4)
	for i := 0; i < 50; i++ {
		sample := w.SampleHonestStratified(8)
		if len(sample) != 8 {
			t.Fatalf("tick %d: want 8 samples, got %d", i, len(sample))
		}
		seen := map[uint32]bool{}
		for _, a := range sample {
			g := a.Group()
			if seen[g] {
				t.Fatalf("duplicate group %d in stratified sample", g)
			}
			seen[g] = true
		}
	}
}

// TestEvilAlwaysOnline：攻击者节点不参与 churn，始终保持在线。
func TestEvilAlwaysOnline(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	w := NewWorld(rng, 500, 2000, 20, 4)
	for i := 0; i < 200; i++ {
		w.Churn(0.5, 0.1)
	}
	for _, a := range w.Evil {
		if !w.IsLive(a) {
			t.Fatalf("evil addr %s went offline", a)
		}
	}
}

// TestNaiveVsHardenedE2E：在同一攻击场景下，加固表的窗口最大攻击者占比
// 必须显著低于朴素表；朴素表必须实际出现高占比包围，否则基线无效。
func TestNaiveVsHardenedE2E(t *testing.T) {
	base := DefaultConfig(StratNaive, 2000, 4)
	trials := 12

	var naiveMax, hardMax float64
	var naiveEclipsed, hardEclipsed int
	for i := 0; i < trials; i++ {
		cn := base
		cn.Strategy = StratNaive
		cn.Seed = 999 + int64(i)
		rn := RunTrial(cn)
		naiveMax += rn.MaxEvilRatio
		if rn.EclipsedMajor {
			naiveEclipsed++
		}

		ch := base
		ch.Strategy = StratHardened
		ch.Seed = 999 + int64(i)
		rh := RunTrial(ch)
		hardMax += rh.MaxEvilRatio
		if rh.EclipsedMajor {
			hardEclipsed++
		}
	}
	naiveMax /= float64(trials)
	hardMax /= float64(trials)

	if naiveEclipsed == 0 {
		t.Fatalf("baseline never eclipsed — attack model too weak (naiveMax=%.2f)", naiveMax)
	}
	if hardMax >= naiveMax {
		t.Fatalf("hardening ineffective: hardMax=%.2f >= naiveMax=%.2f", hardMax, naiveMax)
	}
	// 集中攻击（4 组）下，组上限 4 / 容量 32 给出的结构性上界是 12.5%，
	// 留一定仿真余量，要求窗口峰值不超过 20%。
	if hardMax > 0.20 {
		t.Fatalf("hardened peak evil ratio too high: %.2f", hardMax)
	}
	t.Logf("naive peak evil=%.2f%% hardened peak evil=%.2f%%; naive major-eclipsed %d/%d, hardened %d/%d",
		naiveMax*100, hardMax*100, naiveEclipsed, trials, hardEclipsed, trials)
}

// TestHardenedKeepsLiveness：抗攻击设计不能牺牲正常网络连通性——
// 无攻击稳态下 tried 区应保持接近容量的活跃邻居数。
func TestHardenedKeepsLiveness(t *testing.T) {
	cfg := DefaultConfig(StratHardened, 0, 1)
	cfg.EvilN = 0
	cfg.RestartTick = -1
	cfg.Seed = 7
	r := RunTrial(cfg)
	tcfg := table.DefaultConfig()
	if r.MeanActiveN < float64(tcfg.Cap)*0.75 {
		t.Fatalf("liveness regressed: mean active neighbors %.1f < 75%% of cap %d",
			r.MeanActiveN, tcfg.Cap)
	}
}
