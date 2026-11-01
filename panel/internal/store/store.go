// Package store 是面板的持久层：节点、用户、授权、流量。
//
// 用 SQLite（modernc.org/sqlite，纯 Go 无 cgo），单文件、可备份、无外部依赖。
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ProtoNowhere 是自有扩展协议；其余是 sing-box 原生协议。
const (
	ProtoNowhere     = "nowhere"
	ProtoAnyTLS      = "anytls"
	ProtoHysteria2   = "hysteria2"
	ProtoVLESS       = "vless"
	ProtoTrojan      = "trojan"
	ProtoShadowsocks = "shadowsocks"
)

// Protocols 是面板支持的协议白名单。
var Protocols = []string{
	ProtoNowhere, ProtoAnyTLS, ProtoHysteria2, ProtoVLESS, ProtoTrojan, ProtoShadowsocks,
}

// Machine 是一台被面板编排的机器。
//
// 面板本身跑在任意一台机器上（或本地），通过 SSH 把配置推给其它机器。
// 不引入 agent 是刻意的：SSH 已经在运维手里，多一个常驻进程就多一份攻击面。
type Machine struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	SSHPort int    `json:"ssh_port"`
	SSHUser string `json:"ssh_user"`

	KernelPath  string `json:"kernel_path"`
	ConfigPath  string `json:"config_path"`
	Service     string `json:"service"`
	APIAddr     string `json:"api_addr"`
	StatsBin    string `json:"stats_bin"`
	ClashAddr   string `json:"clash_addr"`
	ControlAddr string `json:"control_addr"`

	Remark string `json:"remark"`
}

// LocalMachine 是面板所在机器的保留名。
const LocalMachine = "local"

// Node 是一个入站（对外提供服务的监听）。
type Node struct {
	Tag string `json:"tag"`
	// Machine 是这台节点所在的机器名；local 表示面板本机。
	Machine string `json:"machine"`
	Proto   string `json:"proto"`
	Listen  string `json:"listen"`
	Port    int    `json:"port"`
	Remark  string `json:"remark"`
	Enabled bool   `json:"enabled"`

	// TLS：mode 为 tls / reality / none
	TLSMode  string `json:"tls_mode"`
	SNI      string `json:"sni"`
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`

	// REALITY
	Dest    string `json:"dest"`
	PrivKey string `json:"priv_key"`
	PubKey  string `json:"pub_key"`
	ShortID string `json:"short_id"`

	// Nowhere
	Morph bool `json:"morph"`

	// Hysteria2
	UpMbps   int `json:"up_mbps"`
	DownMbps int `json:"down_mbps"`

	// Shadowsocks 2022
	SSMethod   string `json:"ss_method"`
	SSPassword string `json:"ss_password"`
}

// User 是一个订阅用户。
type User struct {
	Name string `json:"name"`
	// UUID 给 vless 用
	UUID string `json:"uuid"`
	// Password 给 anytls / trojan / hysteria2 / shadowsocks 用
	Password string `json:"password"`
	// SharedKey 给 nowhere 用（32 位小写十六进制）
	SharedKey string `json:"shared_key"`

	QuotaBytes int64  `json:"quota_bytes"`
	ExpiresAt  int64  `json:"expires_at"`
	Enabled    bool   `json:"enabled"`
	Remark     string `json:"remark"`

	// SubToken 是订阅地址里的凭据，和上面的代理凭据分开。
	// 订阅 URL 会进浏览器历史、日志、剪贴板、二维码截图，
	// 泄露时必须能单独轮换，不能连带把代理凭据一起换掉。
	SubToken string `json:"sub_token"`
}

// Store 是数据库句柄。
type Store struct {
	db *sql.DB
}

// Open 打开（并在需要时创建）数据库。
func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		if err = file.Chmod(0o600); err != nil {
			file.Close()
			return nil, err
		}
		if err = file.Close(); err != nil {
			return nil, err
		}
		for _, suffix := range []string{"-wal", "-shm"} {
			if err = os.Chmod(path+suffix, 0o600); err != nil && !os.IsNotExist(err) {
				return nil, err
			}
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err = s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS nodes (
    tag        TEXT PRIMARY KEY,
    machine    TEXT NOT NULL DEFAULT 'local',
    proto      TEXT NOT NULL,
    listen     TEXT NOT NULL DEFAULT '0.0.0.0',
    port       INTEGER NOT NULL,
    remark     TEXT NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    tls_mode   TEXT NOT NULL DEFAULT 'tls',
    sni        TEXT NOT NULL DEFAULT '',
    cert_path  TEXT NOT NULL DEFAULT '',
    key_path   TEXT NOT NULL DEFAULT '',
    dest       TEXT NOT NULL DEFAULT '',
    priv_key   TEXT NOT NULL DEFAULT '',
    pub_key    TEXT NOT NULL DEFAULT '',
    short_id   TEXT NOT NULL DEFAULT '',
    morph      INTEGER NOT NULL DEFAULT 1,
    up_mbps    INTEGER NOT NULL DEFAULT 0,
    down_mbps  INTEGER NOT NULL DEFAULT 0,
    ss_method  TEXT NOT NULL DEFAULT '',
    ss_password TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS users (
    name        TEXT PRIMARY KEY,
    uuid        TEXT NOT NULL DEFAULT '',
    password    TEXT NOT NULL DEFAULT '',
    shared_key  TEXT NOT NULL DEFAULT '',
    quota_bytes INTEGER NOT NULL DEFAULT 0,
    expires_at  INTEGER NOT NULL DEFAULT 0,
    enabled     INTEGER NOT NULL DEFAULT 1,
    remark      TEXT NOT NULL DEFAULT '',
    sub_token   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS grants (
    node_tag  TEXT NOT NULL,
    user_name TEXT NOT NULL,
    PRIMARY KEY (node_tag, user_name)
);
CREATE TABLE IF NOT EXISTS traffic (
    user_name TEXT NOT NULL,
    day       TEXT NOT NULL,
    up        INTEGER NOT NULL DEFAULT 0,
    down      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_name, day)
);
CREATE TABLE IF NOT EXISTS machines (
    name        TEXT PRIMARY KEY,
    host        TEXT NOT NULL DEFAULT '',
    ssh_port    INTEGER NOT NULL DEFAULT 22,
    ssh_user    TEXT NOT NULL DEFAULT 'root',
    kernel_path TEXT NOT NULL DEFAULT '/usr/local/bin/sbx',
    config_path TEXT NOT NULL DEFAULT '/usr/local/etc/sbx/config.json',
    service     TEXT NOT NULL DEFAULT 'sbx',
    api_addr    TEXT NOT NULL DEFAULT '127.0.0.1:10085',
    stats_bin   TEXT NOT NULL DEFAULT '/usr/local/bin/sb-stats',
    clash_addr  TEXT NOT NULL DEFAULT '127.0.0.1:9090',
    control_addr TEXT NOT NULL DEFAULT '127.0.0.1:10087',
    remark      TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);`)
	if err != nil {
		return err
	}
	if _, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS traffic_samples (
    source TEXT NOT NULL, user_name TEXT NOT NULL, instance TEXT NOT NULL,
    up INTEGER NOT NULL, down INTEGER NOT NULL, PRIMARY KEY(source,user_name,instance)
)`); err != nil {
		return err
	}
	if err = s.ensureSubTokenColumn(); err != nil {
		return err
	}
	// 老库补列：SQLite 的 ADD COLUMN 不支持 IF NOT EXISTS，只能先探测
	if !s.hasColumn("nodes", "machine") {
		if _, err = s.db.Exec(`ALTER TABLE nodes ADD COLUMN machine TEXT NOT NULL DEFAULT 'local'`); err != nil {
			return err
		}
	}
	for _, column := range []struct{ name, fallback string }{
		{"clash_addr", "127.0.0.1:9090"}, {"control_addr", "127.0.0.1:10087"},
	} {
		if !s.hasColumn("machines", column.name) {
			if _, err = s.db.Exec("ALTER TABLE machines ADD COLUMN " + column.name + " TEXT NOT NULL DEFAULT '" + column.fallback + "'"); err != nil {
				return err
			}
		}
	}
	return nil
}

// hasColumn 探测某表是否有某列。
// ensureSubTokenColumn 给老库补上 sub_token 列。
func (s *Store) ensureSubTokenColumn() error {
	if s.hasColumn("users", "sub_token") {
		return nil
	}
	_, err := s.db.Exec(`ALTER TABLE users ADD COLUMN sub_token TEXT NOT NULL DEFAULT ''`)
	return err
}

func (s *Store) hasColumn(table, column string) bool {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, pk int
		var name, ctype string
		var dflt any
		if err = rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return false
		}
		if name == column {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- 机器

// SaveMachine 新增或覆盖一台机器。
func (s *Store) SaveMachine(m Machine) error {
	if m.Name == "" {
		return errors.New("机器名不能为空")
	}
	if m.Name != LocalMachine && m.Host == "" {
		return errors.New("非本机必须填 host")
	}
	if m.SSHPort == 0 {
		m.SSHPort = 22
	}
	if m.SSHUser == "" {
		m.SSHUser = "root"
	}
	if m.KernelPath == "" {
		m.KernelPath = "/usr/local/bin/sbx"
	}
	if m.ConfigPath == "" {
		m.ConfigPath = "/usr/local/etc/sbx/config.json"
	}
	if m.Service == "" {
		m.Service = "sbx"
	}
	if m.APIAddr == "" {
		m.APIAddr = "127.0.0.1:10085"
	}
	if m.StatsBin == "" {
		m.StatsBin = "/usr/local/bin/sb-stats"
	}
	if m.ClashAddr == "" {
		m.ClashAddr = "127.0.0.1:9090"
	}
	if m.ControlAddr == "" {
		m.ControlAddr = "127.0.0.1:10087"
	}
	_, err := s.db.Exec(`
INSERT INTO machines (name, host, ssh_port, ssh_user, kernel_path, config_path, service, api_addr, stats_bin, clash_addr, control_addr, remark)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(name) DO UPDATE SET
  host=excluded.host, ssh_port=excluded.ssh_port, ssh_user=excluded.ssh_user,
  kernel_path=excluded.kernel_path, config_path=excluded.config_path,
  service=excluded.service, api_addr=excluded.api_addr, stats_bin=excluded.stats_bin,
  clash_addr=excluded.clash_addr, control_addr=excluded.control_addr, remark=excluded.remark`,
		m.Name, m.Host, m.SSHPort, m.SSHUser, m.KernelPath, m.ConfigPath,
		m.Service, m.APIAddr, m.StatsBin, m.ClashAddr, m.ControlAddr, m.Remark)
	return err
}

// Machines 返回全部机器，本机永远排最前。
func (s *Store) Machines() ([]Machine, error) {
	rows, err := s.db.Query(`SELECT name, host, ssh_port, ssh_user, kernel_path, config_path,
        service, api_addr, stats_bin, clash_addr, control_addr, remark FROM machines
        ORDER BY CASE name WHEN 'local' THEN 0 ELSE 1 END, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Machine{}
	for rows.Next() {
		var m Machine
		if err = rows.Scan(&m.Name, &m.Host, &m.SSHPort, &m.SSHUser, &m.KernelPath,
			&m.ConfigPath, &m.Service, &m.APIAddr, &m.StatsBin, &m.ClashAddr, &m.ControlAddr, &m.Remark); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Machine 按名字取机器；只有未登记的 local 可使用默认值。
func (s *Store) Machine(name string) (Machine, error) {
	if name == "" {
		name = LocalMachine
	}
	machines, err := s.Machines()
	if err != nil {
		return Machine{}, err
	}
	for _, m := range machines {
		if m.Name == name {
			return m, nil
		}
	}
	if name == LocalMachine {
		return Machine{Name: LocalMachine, Service: "sbx",
			KernelPath: "/usr/local/bin/sbx", ConfigPath: "/usr/local/etc/sbx/config.json",
			APIAddr: "127.0.0.1:10085", StatsBin: "/usr/local/bin/sb-stats",
			ClashAddr: "127.0.0.1:9090", ControlAddr: "127.0.0.1:10087"}, nil
	}
	return Machine{}, fmt.Errorf("机器不存在: %s", name)
}

// DeleteMachine 删除机器；还有节点挂在上面就拒绝，避免留下孤儿节点。
func (s *Store) DeleteMachine(name string) error {
	if name == LocalMachine {
		return errors.New("本机不能删除")
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE machine=?`, name).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("还有 %d 个节点在这台机器上，先移走或删除", count)
	}
	_, err := s.db.Exec(`DELETE FROM machines WHERE name=?`, name)
	return err
}

// ---------------------------------------------------------------- 节点

// SaveNode 新增或覆盖一个节点。
func (s *Store) SaveNode(n Node) error {
	if n.Tag == "" {
		return errors.New("节点 tag 不能为空")
	}
	if !ValidProto(n.Proto) {
		return fmt.Errorf("不支持的协议: %s", n.Proto)
	}
	if _, err := s.Machine(n.Machine); err != nil {
		return err
	}
	if n.TLSMode != "tls" && n.TLSMode != "reality" && n.TLSMode != "none" && n.TLSMode != "" {
		return errors.New("TLS 模式必须为 tls/reality/none")
	}
	if n.Port <= 0 || n.Port > 65535 {
		return fmt.Errorf("端口非法: %d", n.Port)
	}
	if n.Listen == "" {
		n.Listen = "0.0.0.0"
	}
	_, err := s.db.Exec(`
INSERT INTO nodes (tag, machine, proto, listen, port, remark, enabled, tls_mode, sni, cert_path, key_path,
                   dest, priv_key, pub_key, short_id, morph, up_mbps, down_mbps, ss_method, ss_password)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(tag) DO UPDATE SET
  machine=excluded.machine, proto=excluded.proto, listen=excluded.listen, port=excluded.port, remark=excluded.remark,
  enabled=excluded.enabled, tls_mode=excluded.tls_mode, sni=excluded.sni,
  cert_path=excluded.cert_path, key_path=excluded.key_path, dest=excluded.dest,
  priv_key=excluded.priv_key, pub_key=excluded.pub_key, short_id=excluded.short_id,
  morph=excluded.morph, up_mbps=excluded.up_mbps, down_mbps=excluded.down_mbps,
  ss_method=excluded.ss_method, ss_password=excluded.ss_password`,
		n.Tag, orLocal(n.Machine), n.Proto, n.Listen, n.Port, n.Remark, boolInt(n.Enabled), n.TLSMode, n.SNI,
		n.CertPath, n.KeyPath, n.Dest, n.PrivKey, n.PubKey, n.ShortID, boolInt(n.Morph),
		n.UpMbps, n.DownMbps, n.SSMethod, n.SSPassword)
	return err
}

// Nodes 返回全部节点（按端口排序）。
func (s *Store) Nodes() ([]Node, error) {
	rows, err := s.db.Query(`SELECT tag, machine, proto, listen, port, remark, enabled, tls_mode, sni,
        cert_path, key_path, dest, priv_key, pub_key, short_id, morph, up_mbps, down_mbps,
        ss_method, ss_password
        FROM nodes ORDER BY port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		var enabled, morph int
		if err = rows.Scan(&n.Tag, &n.Machine, &n.Proto, &n.Listen, &n.Port, &n.Remark, &enabled, &n.TLSMode,
			&n.SNI, &n.CertPath, &n.KeyPath, &n.Dest, &n.PrivKey, &n.PubKey, &n.ShortID,
			&morph, &n.UpMbps, &n.DownMbps, &n.SSMethod, &n.SSPassword); err != nil {
			return nil, err
		}
		n.Enabled = enabled != 0
		n.Morph = morph != 0
		out = append(out, n)
	}
	return out, rows.Err()
}

// Node 按 tag 取一个节点。
func (s *Store) Node(tag string) (Node, error) {
	nodes, err := s.Nodes()
	if err != nil {
		return Node{}, err
	}
	for _, n := range nodes {
		if n.Tag == tag {
			return n, nil
		}
	}
	return Node{}, fmt.Errorf("节点不存在: %s", tag)
}

// DeleteNode 删除节点及其授权。
func (s *Store) DeleteNode(tag string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM grants WHERE node_tag=?`, tag); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM nodes WHERE tag=?`, tag); err != nil {
		return err
	}
	return tx.Commit()
}

// ---------------------------------------------------------------- 用户

// SaveUser 新增或更新用户；新增时生成凭据，更新时保留已有凭据。
func (s *Store) SaveUser(u User) error {
	if u.Name == "" {
		return errors.New("用户名不能为空")
	}
	if strings.ContainsAny(u.Name, " \t\n") {
		return errors.New("用户名不能含空白字符")
	}
	if strings.Contains(u.Name, ">>>") {
		return errors.New("用户名不能含 >>>")
	}
	if u.QuotaBytes < 0 || u.ExpiresAt < 0 {
		return errors.New("配额和到期时间不能为负数")
	}
	if u.UUID == "" {
		u.UUID = NewUUID()
	}
	if u.Password == "" {
		u.Password = NewSecret()
	}
	if u.SharedKey == "" {
		u.SharedKey = NewNowhereKey()
	}
	_, err := s.db.Exec(`
INSERT INTO users (name, uuid, password, shared_key, quota_bytes, expires_at, enabled, remark, sub_token)
VALUES (?,?,?,?,?,?,?,?,?)
ON CONFLICT(name) DO UPDATE SET
  quota_bytes=excluded.quota_bytes, expires_at=excluded.expires_at,
  enabled=excluded.enabled, remark=excluded.remark
  -- 有意不动 sub_token：订阅凭据只由 SubToken/RotateSubToken 管，
  -- 否则每次改配额都会把用户的订阅地址换掉。`,
		u.Name, u.UUID, u.Password, u.SharedKey, u.QuotaBytes, u.ExpiresAt, boolInt(u.Enabled), u.Remark, u.SubToken)
	return err
}

// Users 返回全部用户。
func (s *Store) Users() ([]User, error) {
	rows, err := s.db.Query(`SELECT name, uuid, password, shared_key, quota_bytes, expires_at,
        enabled, remark, sub_token FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var enabled int
		if err = rows.Scan(&u.Name, &u.UUID, &u.Password, &u.SharedKey, &u.QuotaBytes,
			&u.ExpiresAt, &enabled, &u.Remark, &u.SubToken); err != nil {
			return nil, err
		}
		u.Enabled = enabled != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

// User 按名字取用户。
func (s *Store) User(name string) (User, error) {
	users, err := s.Users()
	if err != nil {
		return User{}, err
	}
	for _, u := range users {
		if u.Name == name {
			return u, nil
		}
	}
	return User{}, fmt.Errorf("用户不存在: %s", name)
}

// DeleteUser 删除用户及其授权与流量记录。
// SubToken 返回用户的订阅 token，没有就生成一个并落库。
//
// 惰性生成：只有真的要用订阅的用户才会有 token，不给所有用户
// 平白多一个可被扫描的凭据。
func (s *Store) SubToken(name string) (string, error) {
	u, err := s.User(name)
	if err != nil {
		return "", err
	}
	if u.SubToken != "" {
		return u.SubToken, nil
	}
	token := NewNowhereKey() // 32 位小写十六进制，够随机
	if _, err = s.db.Exec(`UPDATE users SET sub_token=? WHERE name=?`, token, name); err != nil {
		return "", err
	}
	return token, nil
}

// RotateSubToken 换一把订阅 token。订阅地址泄露时用这个，代理凭据不受影响。
func (s *Store) RotateSubToken(name string) (string, error) {
	token := NewNowhereKey()
	result, err := s.db.Exec(`UPDATE users SET sub_token=? WHERE name=?`, token, name)
	if err != nil {
		return "", err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return "", fmt.Errorf("用户不存在: %s", name)
	}
	return token, nil
}

// UserBySubToken 按订阅 token 反查用户。查不到返回错误。
func (s *Store) UserBySubToken(token string) (User, error) {
	if strings.TrimSpace(token) == "" {
		return User{}, fmt.Errorf("空 token")
	}
	var u User
	row := s.db.QueryRow(`SELECT name, uuid, password, shared_key, quota_bytes,
        expires_at, enabled, remark, sub_token FROM users WHERE sub_token=?`, token)
	if err := row.Scan(&u.Name, &u.UUID, &u.Password, &u.SharedKey, &u.QuotaBytes,
		&u.ExpiresAt, &u.Enabled, &u.Remark, &u.SubToken); err != nil {
		return User{}, fmt.Errorf("订阅 token 无效")
	}
	return u, nil
}

func (s *Store) DeleteUser(name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM grants WHERE user_name=?`,
		`DELETE FROM traffic WHERE user_name=?`,
		`DELETE FROM users WHERE name=?`,
	} {
		if _, err = tx.Exec(q, name); err != nil {
			return err
		}
	}
	// Keep cumulative checkpoints so a delayed sample cannot re-add old usage.
	return tx.Commit()
}

// ---------------------------------------------------------------- 授权

// Grant 把节点授权给用户。
func (s *Store) Grant(nodeTag, userName string) error {
	if _, err := s.Node(nodeTag); err != nil {
		return err
	}
	if _, err := s.User(userName); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO grants (node_tag, user_name) VALUES (?,?)`,
		nodeTag, userName)
	return err
}

// Revoke 取消授权。
func (s *Store) Revoke(nodeTag, userName string) error {
	_, err := s.db.Exec(`DELETE FROM grants WHERE node_tag=? AND user_name=?`, nodeTag, userName)
	return err
}

// UsersForNode 返回某节点被授权的用户名。
func (s *Store) UsersForNode(nodeTag string) ([]string, error) {
	rows, err := s.db.Query(`SELECT user_name FROM grants WHERE node_tag=? ORDER BY user_name`, nodeTag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// NodesForUser 返回某用户被授权的节点 tag。
func (s *Store) NodesForUser(userName string) ([]string, error) {
	rows, err := s.db.Query(`SELECT node_tag FROM grants WHERE user_name=? ORDER BY node_tag`, userName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tag string
		if err = rows.Scan(&tag); err != nil {
			return nil, err
		}
		out = append(out, tag)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- 流量

// AddTraffic 累加某用户某天的流量。
func (s *Store) AddTraffic(userName string, up, down int64, day string) error {
	if up < 0 || down < 0 {
		return errors.New("negative traffic delta")
	}
	if day == "" {
		day = time.Now().Format("2006-01-02")
	}
	_, err := s.db.Exec(`
INSERT INTO traffic (user_name, day, up, down) VALUES (?,?,?,?)
ON CONFLICT(user_name, day) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`,
		userName, day, up, down)
	return err
}

type TrafficSample struct {
	Name     string
	Up, Down int64
}

// RecordTraffic commits counters and their deltas together; retries cannot double bill.
func (s *Store) RecordTraffic(source, instance string, samples []TrafficSample) (int64, int64, error) {
	if instance == "" {
		return 0, 0, errors.New("missing stats instance; upgrade kernel and sb-stats")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	var totalUp, totalDown int64
	day := time.Now().Format("2006-01-02")
	for _, sample := range samples {
		if sample.Up < 0 || sample.Down < 0 {
			return 0, 0, errors.New("negative traffic counter")
		}
		var oldUp, oldDown int64
		err = tx.QueryRow(`SELECT up,down FROM traffic_samples WHERE source=? AND user_name=? AND instance=?`, source, sample.Name, instance).Scan(&oldUp, &oldDown)
		if err != nil && err != sql.ErrNoRows {
			return 0, 0, err
		}
		up, down := sample.Up, sample.Down
		if err == nil {
			up = max(sample.Up-oldUp, 0)
			down = max(sample.Down-oldDown, 0)
			sample.Up = max(sample.Up, oldUp)
			sample.Down = max(sample.Down, oldDown)
		}
		if _, err = tx.Exec(`INSERT INTO traffic (user_name,day,up,down) VALUES (?,?,?,?)
ON CONFLICT(user_name,day) DO UPDATE SET up=up+excluded.up,down=down+excluded.down`, sample.Name, day, up, down); err != nil {
			return 0, 0, err
		}
		if _, err = tx.Exec(`INSERT INTO traffic_samples (source,user_name,instance,up,down) VALUES (?,?,?,?,?)
ON CONFLICT(source,user_name,instance) DO UPDATE SET up=excluded.up,down=excluded.down`, source, sample.Name, instance, sample.Up, sample.Down); err != nil {
			return 0, 0, err
		}
		totalUp += up
		totalDown += down
	}
	if err = tx.Commit(); err != nil {
		return 0, 0, err
	}
	return totalUp, totalDown, nil
}

// Usage 返回某用户的累计用量。
func (s *Store) Usage(userName string) (up, down int64, err error) {
	row := s.db.QueryRow(`SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0) FROM traffic WHERE user_name=?`,
		userName)
	err = row.Scan(&up, &down)
	return
}

// AllUsage 返回每个用户的累计用量。
func (s *Store) AllUsage() (map[string][2]int64, error) {
	rows, err := s.db.Query(`SELECT user_name, COALESCE(SUM(up),0), COALESCE(SUM(down),0)
        FROM traffic GROUP BY user_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][2]int64{}
	for rows.Next() {
		var name string
		var up, down int64
		if err = rows.Scan(&name, &up, &down); err != nil {
			return nil, err
		}
		out[name] = [2]int64{up, down}
	}
	return out, rows.Err()
}

// ResetTraffic 清空某用户的流量记录。
func (s *Store) ResetTraffic(userName string) error {
	_, err := s.db.Exec(`DELETE FROM traffic WHERE user_name=?`, userName)
	return err
}

// ---------------------------------------------------------------- 设置

// Setting 读一个设置项。
func (s *Store) Setting(key, fallback string) string {
	var value string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&value); err != nil {
		return fallback
	}
	return value
}

// SetSetting 写一个设置项。
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings (key,value) VALUES (?,?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// ControlSecret is generated once and shared only with managed kernels.
func (s *Store) ControlSecret() (string, error) {
	secret := NewSecret() + NewSecret()
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO settings (key,value) VALUES ('control_secret',?)`, secret); err != nil {
		return "", err
	}
	var value string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key='control_secret'`).Scan(&value)
	return value, err
}

// ---------------------------------------------------------------- 工具

// orLocal 把空机器名归一成 local。
func orLocal(name string) string {
	if strings.TrimSpace(name) == "" {
		return LocalMachine
	}
	return name
}

// ValidProto 判断协议是否受支持。
func ValidProto(p string) bool {
	for _, known := range Protocols {
		if p == known {
			return true
		}
	}
	return false
}

// NewUUID 生成 v4 UUID。
func NewUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// NewSecret 生成 16 字节 base64 口令（anytls/trojan/hysteria2 用）。
func NewSecret() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64Std(b)
}

// NewNowhereKey 生成 Nowhere 共享密钥：32 位小写十六进制。
//
// 这不是随意选择——nw3 的 wire.ValidateServiceKey 只接受这个格式，
// 写成 base64 会在 portal.New 里直接报错。
func NewNowhereKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// base64Std 是 encoding/base64 的短包装，只为了让上面的生成函数读起来短一点。
func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
