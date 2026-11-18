package table

import (
	"encoding/json"
	"os"
	"sort"
	"sync"

	"eclipseguard/netaddr"
)

// AnchorStore 是信任锚点（重启后用于重连的老邻居）的持久化抽象。
// 生产实现落盘；仿真用内存实现保证多次“重启”间状态延续且可统计。
type AnchorStore interface {
	Load() ([]netaddr.Addr, error)
	Save(addrs []netaddr.Addr) error
}

// memStore 是仿真使用的内存锚点存储。
type memStore struct {
	mu    sync.Mutex
	addrs []netaddr.Addr
}

// NewMemStore 创建空的内存锚点存储。
func NewMemStore() AnchorStore { return &memStore{} }

func (m *memStore) Load() ([]netaddr.Addr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]netaddr.Addr, len(m.addrs))
	copy(out, m.addrs)
	return out, nil
}

func (m *memStore) Save(addrs []netaddr.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addrs = append(m.addrs[:0], addrs...)
	return nil
}

// FileStore 把锚点以 JSON 形式落盘，对应真实节点的 anchors.dat。
// 文件采用 0600 权限：锚点是节点抵御重启包围的根信任，不应被其他用户读取。
type FileStore struct {
	path string
	mu   sync.Mutex
}

// NewFileStore 创建一个落盘锚点存储。
func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

type anchorFile struct {
	Anchors []uint32 `json:"anchors"`
}

func (f *FileStore) Load() ([]netaddr.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var af anchorFile
	if err := json.Unmarshal(data, &af); err != nil {
		return nil, err
	}
	out := make([]netaddr.Addr, len(af.Anchors))
	for i, a := range af.Anchors {
		out[i] = netaddr.Addr(a)
	}
	return out, nil
}

func (f *FileStore) Save(addrs []netaddr.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	af := anchorFile{Anchors: make([]uint32, 0, len(addrs))}
	for _, a := range addrs {
		af.Anchors = append(af.Anchors, uint32(a))
	}
	data, err := json.MarshalIndent(&af, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(f.path, data, 0o600)
}

// pickAnchors 从邻居中挑选锚点：优先 tried 区中存活记录最稳定的老邻居，
// 并限制每个组最多 2 个，保证锚点本身具备组多样性。
func pickAnchors(peers []Peer, max int, now int64) []netaddr.Addr {
	cand := make([]Peer, 0, len(peers))
	for _, p := range peers {
		if p.Probation {
			continue // 观察期节点没有资格成为锚点
		}
		cand = append(cand, p)
	}
	// 越久未失联、入表越早的邻居越可信：GoodTicks 降序、Joined 升序。
	sort.SliceStable(cand, func(i, j int) bool {
		if cand[i].GoodTicks != cand[j].GoodTicks {
			return cand[i].GoodTicks > cand[j].GoodTicks
		}
		return cand[i].Joined < cand[j].Joined
	})
	perGroup := map[uint32]int{}
	out := make([]netaddr.Addr, 0, max)
	for _, p := range cand {
		if len(out) >= max {
			break
		}
		if perGroup[p.Group] >= 2 {
			continue
		}
		out = append(out, p.Addr)
		perGroup[p.Group]++
	}
	return out
}
