package store

import "testing"

// 节点显示名必须符合 <国旗><站点码><编号> 的惯例。
//
// 现状是每台机器手工命名，结果同一台机器上出现 `🇺🇸US2-00 Reality` 和
// `🇺🇸US2-01` 混用，而别的机器是 `🇯🇵JP01` 这种干净格式——订阅里看起来乱。
func TestConventionalRemark(t *testing.T) {
	for _, ok := range []string{"🇭🇰HK01", "🇯🇵JP02", "🇺🇸US201", "🇸🇬SG06"} {
		if !ConventionalRemark(ok) {
			t.Errorf("合法名称被判错: %q", ok)
		}
	}
	// 历史遗留写法：带连字符 + 协议名、无国旗、编号不足位
	for _, bad := range []string{
		"🇺🇸US2-00 Reality", "US01", "🇭🇰HK1", "🇯🇵JP01 节点", "",
	} {
		if ConventionalRemark(bad) {
			t.Errorf("不合规名称被放行: %q", bad)
		}
	}
}
