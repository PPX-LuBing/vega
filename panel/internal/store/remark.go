package store

import "regexp"

// remarkPattern 是节点显示名的惯例：<国旗><站点码><编号>，如 🇭🇰HK01、🇺🇸US201。
//
// 国旗在 Go 正则里是一个 emoji 符号序列，用 \p{So} 匹配而不是硬数 rune 数。
// 站点码 2-3 位大写字母，编号 2-3 位数字——**不带连字符、不带协议名**，
// 因为订阅里节点名是给人看的，`🇺🇸US2-00 Reality` 这种写法在列表里很扎眼。
var remarkPattern = regexp.MustCompile(`^\p{So}+([A-Z]{2,3})(\d{2,3})$`)

// ConventionalRemark 报告名称是否符合惯例。只用于提示，不参与校验。
func ConventionalRemark(remark string) bool {
	return remarkPattern.MatchString(remark)
}
