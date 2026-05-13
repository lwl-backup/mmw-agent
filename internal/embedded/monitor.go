package embedded

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/features/stats"
)

// AutoSpeedLimitConfig 自动限速配置（Master 下发）。
type AutoSpeedLimitConfig struct {
	Enable        bool   `json:"enable"`
	Limit         uint64 `json:"limit"`          // 触发阈值 (Bytes/s)
	WarnTimes     int    `json:"warn_times"`     // 连续超速次数触发
	LimitSpeed    uint64 `json:"limit_speed"`    // 限速后速率 (Bytes/s)
	LimitDuration int    `json:"limit_duration"` // 限速持续时间 (秒)
}

// StartAutoSpeedMonitor 启动自动限速监控。
func (e *EmbeddedXray) StartAutoSpeedMonitor(interval time.Duration, config AutoSpeedLimitConfig) {
	if !config.Enable || config.Limit == 0 {
		return
	}
	if config.WarnTimes <= 0 {
		config.WarnTimes = 3
	}
	if config.LimitDuration <= 0 {
		config.LimitDuration = 60
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		warnCount := make(map[string]int)
		var mu sync.Mutex

		for range ticker.C {
			e.mu.RLock()
			sm := e.statsManager
			l := e.GetLimiter()
			e.mu.RUnlock()

			if sm == nil || l == nil {
				continue
			}

			userTraffic := make(map[string]int64)
			type counterLister interface {
				VisitCounters(func(string, stats.Counter) bool)
			}
			if lister, ok := sm.(counterLister); ok {
				lister.VisitCounters(func(name string, c stats.Counter) bool {
					if !strings.HasPrefix(name, "user>>>") {
						return true
					}
					parts := strings.Split(name, ">>>")
					if len(parts) != 4 || parts[2] != "traffic" {
						return true
					}
					email := parts[1]
					value := c.Value()
					userTraffic[email] += value
					return true
				})
			}

			threshold := int64(config.Limit) * int64(interval.Seconds())
			mu.Lock()
			for email, traffic := range userTraffic {
				if traffic > threshold {
					warnCount[email]++
					if warnCount[email] >= config.WarnTimes {
						log.Printf("[AutoLimit] User %s exceeded speed limit (%d times), applying temp limit %d Bytes/s for %ds",
							email, warnCount[email], config.LimitSpeed, config.LimitDuration)

						// Apply temporary speed limit across all inbounds
						l.InboundInfo.Range(func(key, _ interface{}) bool {
							tag := key.(string)
							l.SetUserSpeed(tag, email, config.LimitSpeed)
							return true
						})

						warnCount[email] = 0
						emailCopy := email
						time.AfterFunc(time.Duration(config.LimitDuration)*time.Second, func() {
							l.InboundInfo.Range(func(key, _ interface{}) bool {
								tag := key.(string)
								l.SetUserSpeed(tag, emailCopy, 0) // restore
								return true
							})
							log.Printf("[AutoLimit] User %s speed limit restored", emailCopy)
						})
					}
				} else {
					delete(warnCount, email)
				}
			}
			mu.Unlock()
		}
	}()
}
