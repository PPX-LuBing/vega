package option

// NowhereInboundOptions 是 Nowhere(nw3) Portal 入站的配置。
//
// 与上游 nowhere-go/portal.Config 的对应关系：
//
//	SharedKey    -> portal.Config.SharedKey（单密钥模式）
//	Users        -> 多用户模式，每个用户一把共享密钥
//	Morph        -> portal.Config.Morph
//	UploadMbps   -> portal.Config.UploadMbps
//	DownloadMbps -> portal.Config.DownloadMbps
//
// SharedKey 与 Users 二选一：SharedKey 用于兼容官方 Vector/Anywhere 客户端
// 的单密钥 Portal；Users 用于面板按用户管理（AuthFrame 没有身份字段，
// 服务端靠逐个试解密钥来识别用户）。
type NowhereInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer

	// SharedKey 单密钥模式的共享密钥（base64）。
	SharedKey string `json:"shared_key,omitempty"`

	// Users 多用户模式。与 SharedKey 互斥。
	Users []NowhereUser `json:"users,omitempty"`

	// Morph 是否启用 Morph TCP/UDP prelude 伪装。nw3 默认开启，
	// 关闭会让 nw3 客户端无法连接（3.2 Portal 强制校验 prelude）。
	Morph *bool `json:"morph,omitempty"`

	// 限速（Mbps）。0 表示不限。
	UploadMbps   int `json:"upload_mbps,omitempty"`
	DownloadMbps int `json:"download_mbps,omitempty"`

	// Egress 允许一个 Egress 注册（Portal 链式）。
	Egress bool `json:"egress,omitempty"`

	// ControlAddr 是运行期改用户的控制端点，只允许绑回环。
	// 默认 127.0.0.1:10087；设为 "off" 可关闭。
	ControlAddr string `json:"control_addr,omitempty"`
}

// NowhereUser 是一个 Nowhere 用户。
type NowhereUser struct {
	Name string `json:"name,omitempty"`
	// SharedKey 该用户的共享密钥（base64）。留空表示由面板生成。
	SharedKey string `json:"shared_key,omitempty"`
}

// NowhereOutboundOptions 是 Nowhere Vector（客户端）出站的配置。
type NowhereOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer

	SharedKey    string `json:"shared_key,omitempty"`
	Morph        *bool  `json:"morph,omitempty"`
	UploadMbps   int    `json:"upload_mbps,omitempty"`
	DownloadMbps int    `json:"download_mbps,omitempty"`
}
