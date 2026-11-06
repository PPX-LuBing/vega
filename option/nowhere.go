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

	// SharedKey is exactly 32 lowercase hexadecimal characters.
	SharedKey string `json:"shared_key,omitempty"`

	// Users 多用户模式。与 SharedKey 互斥。
	Users []NowhereUser `json:"users,omitempty"`

	// Carrier selects tcp (default), quic, or both on the same port.
	Carrier string `json:"carrier,omitempty"`

	// Morph defaults on. Both peers must use the same setting.
	Morph *bool `json:"morph,omitempty"`

	// 限速（Mbps）。0 表示不限。
	UploadMbps   int `json:"upload_mbps,omitempty"`
	DownloadMbps int `json:"download_mbps,omitempty"`

	// Egress enables remote exit registrations; use a nowhere-egress outbound
	// referencing this inbound to route traffic through those registrations.
	Egress bool `json:"egress,omitempty"`

	// ControlAddr 是运行期改用户的控制端点，只允许绑回环。
	// Disabled unless ControlSecret is set; "off" explicitly disables it.
	ControlAddr   string `json:"control_addr,omitempty"`
	ControlSecret string `json:"control_secret,omitempty"`
}

// NowhereUser 是一个 Nowhere 用户。
type NowhereUser struct {
	Name string `json:"name,omitempty"`
	// SharedKey is exactly 32 lowercase hexadecimal characters.
	SharedKey string `json:"shared_key,omitempty"`
}

// NowhereOutboundOptions 是 Nowhere Vector（客户端）出站的配置。
type NowhereOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer

	SharedKey    string `json:"shared_key,omitempty"`
	Carrier      string `json:"carrier,omitempty"`
	Morph        *bool  `json:"morph,omitempty"`
	UploadMbps   int    `json:"upload_mbps,omitempty"`
	DownloadMbps int    `json:"download_mbps,omitempty"`
}

type NowhereEgressOutboundOptions struct {
	Portal string `json:"portal"`
}

// The exit actively connects to Portal and routes received flows locally.
type NowhereEgressServiceOptions struct {
	NowhereOutboundOptions
	User string `json:"user,omitempty"`
}
