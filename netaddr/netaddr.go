// Package netaddr 表示仿真网络中的节点地址及其分组。
//
// 真实 P2P 网络里攻击者通常可以廉价地拿到同一网段（如同一 /16）内的大量
// IP，因此“地址数量”并不等于“身份多样性”。这里把地址空间按 /16 分组
// （group），邻居表的多样性规则全部以组为单位生效。
package netaddr

import "fmt"

// Addr 是一个 32 位仿真地址。
type Addr uint32

// Group 返回地址所属的 /16 组（高 16 位）。
func (a Addr) Group() uint32 { return uint32(a) >> 16 }

// String 以点分十进制形式输出，便于调试。
func (a Addr) String() string {
	v := uint32(a)
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// Make 由四个字节构造地址。
func Make(a, b, c, d byte) Addr {
	return Addr(uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d))
}

// FromGroupHost 由组号和组内主机号构造地址。
func FromGroupHost(group uint32, host uint32) Addr {
	return Addr((group << 16) | (host & 0xffff))
}
