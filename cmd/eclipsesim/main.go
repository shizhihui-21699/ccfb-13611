// eclipsesim 批量运行仿真试验，对比朴素邻居表与加固邻居表在不同攻击
// 规模、攻击者分布方式和节点重启场景下的被包围概率。
package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"eclipseguard/sim"
	"eclipseguard/stats"
)

type profile struct {
	label      string
	evilN      int
	evilGroups int
	restart    bool
}

// profiles 覆盖三类对抗条件：
//  1. 集中攻击：攻击者只占 4 个 /16 组（同机房批量开假节点）；
//  2. 分散攻击：攻击者铺到 32 个组，试图绕开组多样性上限；
//  3. 重启攻击对照：同一场景关闭重启，量化持久化锚点的独立贡献。
func profiles() []profile {
	return []profile{
		{"concentrated-500", 500, 4, true},
		{"concentrated-1000", 1000, 4, true},
		{"concentrated-2000", 2000, 4, true},
		{"concentrated-4000", 4000, 4, true},
		{"distributed-1000", 1000, 32, true},
		{"distributed-2000", 2000, 32, true},
		{"restart-off-2000", 2000, 4, false},
	}
}

func main() {
	trials := flag.Int("trials", 200, "每个场景每种策略的独立试验次数")
	quick := flag.Bool("quick", false, "快速冒烟模式（等价于 -trials 30）")
	outDir := flag.String("outdir", "results", "CSV 输出目录")
	baseSeed := flag.Int64("seed", 20261119, "基础随机种子")
	flag.Parse()

	if *quick {
		*trials = 30
	}
	strategies := []sim.Strategy{sim.StratNaive, sim.StratHardened}
	prof := profiles()

	fmt.Printf("eclipse-attack simulation: %d scenarios x %d strategies x %d trials\n",
		len(prof), len(strategies), *trials)
	fmt.Printf("honest nodes: 1000 (40 /16 groups), attack window: 250 ticks, flood: 16 addrs/tick\n\n")

	var ags []stats.Aggregate
	started := time.Now()

	for pi, p := range prof {
		for si, strat := range strategies {
			cfg := sim.DefaultConfig(strat, p.evilN, p.evilGroups)
			if !p.restart {
				cfg.RestartTick = -1
			}
			results := make([]sim.TrialResult, 0, *trials)
			for i := 0; i < *trials; i++ {
				// 同一 profile 下两种策略使用相同种子序列，配对比试，
				// 消除网络实例差异对对比结论的干扰。
				cfg.Seed = *baseSeed + int64(pi)*100000 + int64(i)
				_ = si
				r := sim.RunTrial(cfg)
				results = append(results, r)
			}
			ag := stats.AggregateResults(p.label, cfg, results)
			ags = append(ags, ag)
			fmt.Printf("[%2d/%d] %-20s %-9s done\n",
				pi*len(strategies)+si+1, len(prof)*len(strategies), p.label, strat)
		}
	}

	stats.PrintTable(ags)
	path := *outDir + "/eclipse_results.csv"
	if err := stats.WriteCSV(path, ags); err != nil {
		log.Fatalf("write csv: %v", err)
	}
	fmt.Printf("CSV written to %s (elapsed %s)\n", path, time.Since(started).Round(time.Millisecond))
}
