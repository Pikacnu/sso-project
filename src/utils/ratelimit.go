package utils

import (
	"errors"
	"sync"
	"time"
)

var GlobalRateLimitInstance *RateLimitConfig

type RateLimitConfig struct {
	RequestTimeMap      map[string][]time.Time
	RequestsPerMinute   int
	RequestTimeMapMutex sync.RWMutex
	RequestLimiterFunc  func(key string) bool
}

func RateLimitCreator(
	RequestsPerMinute int,
) error {
	if RequestsPerMinute <= 0 {
		return errors.New("No rate limiting can be set to 0 or negative") // No rate limiting if set to 0 or negative
	}
	if GlobalRateLimitInstance != nil {
		return errors.New("Rate limit instance already exists")
	}

	rl := &RateLimitConfig{
		RequestTimeMap:    make(map[string][]time.Time),
		RequestsPerMinute: RequestsPerMinute,
	}

	rl.RequestLimiterFunc = func(key string) bool {
		rl.RequestTimeMapMutex.RLock()
		defer rl.RequestTimeMapMutex.RUnlock()

		now := time.Now()
		requestTimes, exists := rl.RequestTimeMap[key]
		if !exists {
			rl.RequestTimeMap[key] = []time.Time{now}
			return true
		}
		var recentTimes []time.Time
		for _, t := range requestTimes {
			if now.Sub(t) < time.Minute {
				recentTimes = append(recentTimes, t)
			}
		}
		if len(recentTimes) < rl.RequestsPerMinute {
			rl.RequestTimeMap[key] = append(recentTimes, now)
			return true
		}
		return false
	}

	GlobalRateLimitInstance = rl

	go rl.Cleaner()

	return nil
}

func (rl *RateLimitConfig) Cleaner() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.RequestTimeMapMutex.Lock()
		now := time.Now()
		for key, times := range rl.RequestTimeMap {
			var recentTimes []time.Time
			for _, t := range times {
				if now.Sub(t) < time.Minute {
					recentTimes = append(recentTimes, t)
				}
			}
			if len(recentTimes) > 0 {
				rl.RequestTimeMap[key] = recentTimes
			} else {
				delete(rl.RequestTimeMap, key)
			}
		}
		rl.RequestTimeMapMutex.Unlock()
	}
}
