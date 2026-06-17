// 方案 K — agent 端 per-user 瞬时速率采样。每 1s 拉一次 xray stats(non-destructive Value()),
// 维护 60 节点环形 buffer,上报时算 3 档窗口平均(1s instant / 5s avg / 30s avg)。
//
// 设计原则:
//   - 数据源跟 CollectStats().User 同源(non-destructive Value),不影响 master 累计 delta 逻辑
//   - xray 重启检测:current < lastTotal → counter 归零 → 重置该 user 的 buffer
//   - 用户消失检测:本轮 stats 没有的 email 直接从 map 删,避免内存泄露
//   - 仅 embedded 模式生效;外部 xray 模式 collectUserSpeeds() 返回 nil,master 收到 nil 跳过
package agent

import (
	"context"
	"sync"
	"time"
)

const userRingCap = 60 // 60 个样本 = 60 秒历史(1s 采样)

// userSample 单条快照:时间戳 + 上下行累计字节
type userSample struct {
	tsUnixNano int64
	uplink     int64
	downlink   int64
}

// userRingBuf per-email 环形 buffer
type userRingBuf struct {
	samples       [userRingCap]userSample
	head          int   // 下一个写入位置
	count         int   // 已填充样本数(≤cap)
	lastUplinkRaw int64 // 上一次累计值,用于检测 xray 重启(current < last → 归零 → reset)
	lastDownRaw   int64
}

// userRateRing 全局 ring 状态
type userRateRing struct {
	mu      sync.RWMutex
	samples map[string]*userRingBuf
}

func newUserRateRing() *userRateRing {
	return &userRateRing{samples: make(map[string]*userRingBuf)}
}

// sampleUserRates 拉取当前 user 累计,更新所有环形 buffer。每秒由独立 goroutine 调一次。
// 入参:map[email] -> (uplink_cumulative, downlink_cumulative)
func (r *userRateRing) sampleUserRates(now time.Time, currentUserStats map[string][2]int64) {
	if currentUserStats == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// 清理本轮 stats 里不存在的 email(用户被删除 / xray 重启清空)
	for email := range r.samples {
		if _, ok := currentUserStats[email]; !ok {
			delete(r.samples, email)
		}
	}

	nowNs := now.UnixNano()
	for email, pair := range currentUserStats {
		up, down := pair[0], pair[1]
		rb := r.samples[email]
		if rb == nil {
			rb = &userRingBuf{lastUplinkRaw: up, lastDownRaw: down}
			r.samples[email] = rb
		}
		// xray 重启检测:任一字段倒退 → counter 归零 → 重置 buffer
		if up < rb.lastUplinkRaw || down < rb.lastDownRaw {
			*rb = userRingBuf{lastUplinkRaw: up, lastDownRaw: down}
		}
		rb.lastUplinkRaw = up
		rb.lastDownRaw = down
		rb.samples[rb.head] = userSample{tsUnixNano: nowNs, uplink: up, downlink: down}
		rb.head = (rb.head + 1) % userRingCap
		if rb.count < userRingCap {
			rb.count++
		}
	}
}

// UserRateOutput 单 email 3 档窗口平均速率(Bytes/sec)。跟 master 端 traffic.UserRateEntry 字段对齐,
// 但 agent 独立定义类型避免引 master 包。
type UserRateOutput struct {
	UpBps1s    int64 `json:"up_bps_1s"`
	DownBps1s  int64 `json:"down_bps_1s"`
	UpBps5s    int64 `json:"up_bps_5s"`
	DownBps5s  int64 `json:"down_bps_5s"`
	UpBps30s   int64 `json:"up_bps_30s"`
	DownBps30s int64 `json:"down_bps_30s"`
}

// collectUserSpeeds 返回所有 email 的 3 档速率。窗口不够时降级:
//   - 仅 1 个样本 → 跳过该 email(算不出 rate)
//   - 5s/30s 窗口不够 → 用所有可用样本算 avg(实际 dt 用首尾 ts 差)
func (r *userRateRing) collectUserSpeeds() map[string]UserRateOutput {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]UserRateOutput, len(r.samples))
	for email, rb := range r.samples {
		if rb.count < 2 {
			continue
		}
		up1s, down1s := rb.avgRate(1)
		up5s, down5s := rb.avgRate(5)
		up30s, down30s := rb.avgRate(30)
		// 全 0 不上报(没流量的用户不占带宽,master 视角等同 stale → 0)
		if up1s == 0 && down1s == 0 && up5s == 0 && down5s == 0 && up30s == 0 && down30s == 0 {
			continue
		}
		out[email] = UserRateOutput{
			UpBps1s: up1s, DownBps1s: down1s,
			UpBps5s: up5s, DownBps5s: down5s,
			UpBps30s: up30s, DownBps30s: down30s,
		}
	}
	return out
}

// runUserRateSampler 由 Start() 起,每 1s 拉 xray stats(non-destructive Value)更新环形 buffer。
// 仅 embedded 模式有效;调用前 caller 已保证 c.embeddedXray != nil。
func (c *Client) runUserRateSampler(ctx context.Context) {
	defer c.wg.Done()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case t := <-ticker.C:
			c.sampleUserRatesOnce(t)
		}
	}
}

// sampleUserRatesOnce 拉一次 stats 转成 map[email]{up, down} 给 ringbuffer。
// 走统一的 collectLocalMetrics() 拉:
//   - embedded 模式:直接读 in-memory stats.Manager Value()(~μs 级)
//   - external 模式:HTTP GET xray /debug/vars,localhost RTT ~ms 级,1s 一次开销可接受
// 单次 fetch 失败(xray 暂时不可达 / metrics 端口未配)直接 return,不污染 buffer。
func (c *Client) sampleUserRatesOnce(now time.Time) {
	if c.userRates == nil {
		return
	}
	stats, err := c.collectLocalMetrics()
	if err != nil || stats == nil || len(stats.User) == 0 {
		return
	}
	cur := make(map[string][2]int64, len(stats.User))
	for email, td := range stats.User {
		cur[email] = [2]int64{td.Uplink, td.Downlink}
	}
	c.userRates.sampleUserRates(now, cur)
}

// CollectUserRatesForReport 上报时调用,返回当前所有 email 的 3 档速率。
// 老 master 不识别 user_rates 字段 → 直接忽略,本上报无害。
func (c *Client) CollectUserRatesForReport() map[string]UserRateOutput {
	if c.userRates == nil {
		return nil
	}
	return c.userRates.collectUserSpeeds()
}

// avgRate 算 N 秒窗口的平均速率(uplink, downlink)。N 秒不够时用所有可用样本(elapsed 取实际差)。
func (rb *userRingBuf) avgRate(seconds int) (upBps, downBps int64) {
	if rb.count < 2 {
		return 0, 0
	}
	available := rb.count
	if available > seconds+1 {
		available = seconds + 1
	}
	latestIdx := (rb.head - 1 + userRingCap) % userRingCap
	oldestIdx := (rb.head - available + userRingCap) % userRingCap
	latest := rb.samples[latestIdx]
	oldest := rb.samples[oldestIdx]
	elapsedSec := float64(latest.tsUnixNano-oldest.tsUnixNano) / 1e9
	if elapsedSec <= 0 {
		return 0, 0
	}
	deltaUp := latest.uplink - oldest.uplink
	deltaDown := latest.downlink - oldest.downlink
	if deltaUp > 0 {
		upBps = int64(float64(deltaUp) / elapsedSec)
	}
	if deltaDown > 0 {
		downBps = int64(float64(deltaDown) / elapsedSec)
	}
	return upBps, downBps
}
