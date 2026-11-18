// Package stats 汇总多次仿真试验，计算包围概率、置信区间并输出 CSV。
package stats

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"

	"eclipseguard/sim"
)

// Aggregate 是同一条件下多次试验的聚合结果。
type Aggregate struct {
	Label      string
	Strategy   sim.Strategy
	EvilN      int
	EvilGroups int
	Trials     int

	FullProb  float64 // 窗口内发生 100% 包围的比例
	MajorProb float64 // 攻击者占比 >=75% 的比例
	HalfProb  float64 // 攻击者占比 >=50% 的比例
	FullLo    float64 // FullProb 的 Wilson 95% 置信区间下界
	FullHi    float64
	MajorLo   float64
	MajorHi   float64

	PostRestartFullProb  float64
	PostRestartMajorProb float64
	PostRestartMeanRatio float64

	MeanMaxRatio      float64 // 窗口峰值攻击者占比的跨试验均值
	MeanMaxGroupRatio float64 // 窗口峰值单组占比的跨试验均值（组多样性防线的实际效果）
	MeanRatio         float64
	MeanActiveN       float64
}

// AggregateResults 聚合一组试验结果。
func AggregateResults(label string, cfg sim.Config, results []sim.TrialResult) Aggregate {
	n := len(results)
	ag := Aggregate{Label: label, Strategy: cfg.Strategy, EvilN: cfg.EvilN, EvilGroups: cfg.EvilGroups, Trials: n}
	var sumMax, sumMean, sumActive, sumPostRatio, sumMaxGroup float64
	for _, r := range results {
		if r.EclipsedFull {
			ag.FullProb++
		}
		if r.EclipsedMajor {
			ag.MajorProb++
		}
		if r.EclipsedHalf {
			ag.HalfProb++
		}
		if r.PostRestartFull {
			ag.PostRestartFullProb++
		}
		if r.PostRestartMajor {
			ag.PostRestartMajorProb++
		}
		sumPostRatio += r.PostRestartEvilRatio
		sumMax += r.MaxEvilRatio
		sumMaxGroup += r.MaxGroupRatio
		sumMean += r.MeanEvilRatio
		sumActive += r.MeanActiveN
	}
	ag.FullProb /= float64(n)
	ag.MajorProb /= float64(n)
	ag.HalfProb /= float64(n)
	ag.PostRestartFullProb /= float64(n)
	ag.PostRestartMajorProb /= float64(n)
	ag.PostRestartMeanRatio = sumPostRatio / float64(n)
	ag.MeanMaxRatio = sumMax / float64(n)
	ag.MeanMaxGroupRatio = sumMaxGroup / float64(n)
	ag.MeanRatio = sumMean / float64(n)
	ag.MeanActiveN = sumActive / float64(n)
	ag.FullLo, ag.FullHi = wilson(ag.FullProb, n)
	ag.MajorLo, ag.MajorHi = wilson(ag.MajorProb, n)
	return ag
}

// wilson 返回二项比例的 Wilson 95% 置信区间（z=1.96）。
// 相比正态近似，在概率接近 0 或 1、试验数有限时仍然有效。
func wilson(p float64, n int) (float64, float64) {
	if n == 0 {
		return 0, 0
	}
	const z = 1.96
	z2 := z * z
	denom := 1 + z2/float64(n)
	center := (p + z2/(2*float64(n))) / denom
	half := (z * math.Sqrt((p*(1-p)+z2/(4*float64(n)))/float64(n))) / denom
	lo := center - half
	hi := center + half
	return math.Max(0, lo), math.Min(1, hi)
}

// pct 把比例格式化为百分数字符串。
func pct(x float64) string { return fmt.Sprintf("%.1f%%", x*100) }

// PrintTable 以对齐表格形式把聚合结果打印到标准输出。
func PrintTable(ags []Aggregate) {
	fmt.Printf("\n%-20s %-9s %7s %6s | %14s %14s | %13s %13s | %10s %10s | %8s\n",
		"scenario", "strategy", "evilN", "grps",
		"P(eclip 100%)", "P(eclip>=75%)", "P(rst 100%)", "P(rst>=75%)",
		"peak evil", "peak 1grp", "mean act")
	fmt.Println(repeat("-", 142))
	for _, a := range ags {
		fmt.Printf("%-20s %-9s %7d %6d | %13s [%4.1f,%4.1f] %13s [%4.1f,%4.1f] | %13s %13s | %9s %10s | %8.1f\n",
			a.Label, a.Strategy, a.EvilN, a.EvilGroups,
			pct(a.FullProb), a.FullLo*100, a.FullHi*100,
			pct(a.MajorProb), a.MajorLo*100, a.MajorHi*100,
			pct(a.PostRestartFullProb), pct(a.PostRestartMajorProb),
			pct(a.MeanMaxRatio), pct(a.MeanMaxGroupRatio),
			a.MeanActiveN)
	}
	fmt.Println()
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

var csvHeader = []string{
	"scenario", "strategy", "evil_n", "evil_groups", "trials",
	"p_eclipse_full", "p_eclipse_full_lo", "p_eclipse_full_hi",
	"p_eclipse_major", "p_eclipse_major_lo", "p_eclipse_major_hi",
	"p_eclipse_half",
	"p_restart_full", "p_restart_major", "post_restart_mean_evil_ratio",
	"mean_max_evil_ratio", "mean_max_group_ratio",
	"mean_evil_ratio", "mean_active_neighbors",
}

// WriteCSV 把聚合结果写入 CSV 文件，便于后续绘图或报告引用。
func WriteCSV(path string, ags []Aggregate) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(csvHeader); err != nil {
		return err
	}
	for _, a := range ags {
		row := []string{
			a.Label, string(a.Strategy), strconv.Itoa(a.EvilN), strconv.Itoa(a.EvilGroups), strconv.Itoa(a.Trials),
			strconv.FormatFloat(a.FullProb, 'f', 4, 64),
			strconv.FormatFloat(a.FullLo, 'f', 4, 64),
			strconv.FormatFloat(a.FullHi, 'f', 4, 64),
			strconv.FormatFloat(a.MajorProb, 'f', 4, 64),
			strconv.FormatFloat(a.MajorLo, 'f', 4, 64),
			strconv.FormatFloat(a.MajorHi, 'f', 4, 64),
			strconv.FormatFloat(a.HalfProb, 'f', 4, 64),
			strconv.FormatFloat(a.PostRestartFullProb, 'f', 4, 64),
			strconv.FormatFloat(a.PostRestartMajorProb, 'f', 4, 64),
			strconv.FormatFloat(a.PostRestartMeanRatio, 'f', 4, 64),
			strconv.FormatFloat(a.MeanMaxRatio, 'f', 4, 64),
			strconv.FormatFloat(a.MeanMaxGroupRatio, 'f', 4, 64),
			strconv.FormatFloat(a.MeanRatio, 'f', 4, 64),
			strconv.FormatFloat(a.MeanActiveN, 'f', 2, 64),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
