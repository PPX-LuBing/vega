package kernel

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

func ParseQuotaGB(text string) (int64, error) {
	value, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
	bytes := value * (1 << 30)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || (value > 0 && bytes < 1) || bytes >= float64(math.MaxInt64) {
		return 0, fmt.Errorf("配额须为 0（不限量）或至少 1 字节的有限数字，且小于 8589934592 GB")
	}
	return int64(bytes), nil
}

func ParseExpiryDays(text string) (int64, error) {
	days, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || days < 0 || days > 365000 {
		return 0, fmt.Errorf("有效天数必须为 0 到 365000 的整数，0 表示永久")
	}
	if days == 0 {
		return 0, nil
	}
	return time.Now().AddDate(0, 0, days).Unix(), nil
}
