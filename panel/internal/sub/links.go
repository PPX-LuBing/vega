package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

func Links(st *store.Store, user store.User, encoded bool) (string, []string, error) {
	eps, skipped, err := Endpoints(st, user)
	if err != nil {
		return "", nil, err
	}
	var lines []string
	for _, e := range eps {
		link, err := shareLink(e)
		if err != nil {
			skipped = append(skipped, e.Node.Tag+": "+err.Error())
			continue
		}
		lines = append(lines, link)
	}
	if len(lines) == 0 {
		return "", skipped, fmt.Errorf("no usable share links")
	}
	body := strings.Join(lines, "\n") + "\n"
	if encoded {
		body = base64.StdEncoding.EncodeToString([]byte(body)) + "\n"
	}
	return body, skipped, nil
}

func shareLink(e endpoint) (string, error) {
	n, u := e.Node, e.User
	if n.EntrySNI != "" {
		n.SNI = n.EntrySNI
	}
	if n.Proto == store.ProtoNowhere {
		return nowhereURI(e)
	}
	address := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	q := url.Values{}
	if n.TLSMode == "reality" {
		q.Set("security", "reality")
		q.Set("pbk", n.PubKey)
		q.Set("sid", n.ShortID)
		q.Set("flow", "xtls-rprx-vision")
	} else if n.TLSMode != "none" {
		q.Set("security", "tls")
	} else {
		q.Set("security", "none")
	}
	if n.SNI != "" {
		q.Set("sni", n.SNI)
	}
	if n.Fingerprint != "" {
		q.Set("fp", n.Fingerprint)
	}
	if n.TLSMode == "tls" && n.ECHConfig != "" {
		// v2rayN / Xray 系从分享链接的 `ech` 查询参数读 ECH（见 v2rayN 的
		// ServiceLib/Handler/Fmt/BaseFmt.cs：GetQueryDecoded(query, "ech")），
		// 值要**裸 base64**，客户端自己会包成 `ECH CONFIGS` PEM。
		//
		// 实测 v2rayN 只在 BaseFmt 系（vless / trojan / hysteria2）实现了这个参数，
		// vmess 的 JSON 和 anytls / tuic 的链接都没读。多写一个参数不会有害——
		// 不认识的解析器会忽略它，认识它的客户端才用。
		if b64 := echConfigB64(n.ECHConfig); b64 != "" {
			q.Set("ech", b64)
		}
	}
	transport := n.Transport
	if transport == "" {
		transport = "tcp"
	}
	q.Set("type", transport)
	if n.Path != "" {
		q.Set("path", n.Path)
	}
	if n.Host != "" {
		q.Set("host", n.Host)
	}
	if n.GRPCService != "" {
		q.Set("serviceName", n.GRPCService)
	}
	credential := u.Password
	switch n.Proto {
	case store.ProtoVLESS:
		credential = u.UUID
		q.Set("encryption", "none")
	case store.ProtoVMess:
		security := ""
		if n.TLSMode != "none" {
			security = "tls"
		}
		path := n.Path
		if transport == "grpc" {
			path = n.GRPCService
		}
		body, err := json.Marshal(map[string]any{"v": "2", "ps": e.Name(), "add": e.Host, "port": strconv.Itoa(e.Port), "id": u.UUID, "aid": "0", "scy": "auto", "net": transport, "type": "none", "host": n.Host, "path": path, "tls": security, "sni": n.SNI, "fp": n.Fingerprint})
		if err != nil {
			return "", err
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(body), nil
	case store.ProtoShadowsocks:
		method := n.SSMethod
		if method == "" {
			method = "2022-blake3-aes-128-gcm"
		}
		password := n.SSPassword + ":" + u.Password
		credential = base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
		return "ss://" + credential + "@" + address + "#" + url.PathEscape(e.Name()), nil
	case store.ProtoTrojan, store.ProtoHysteria2, store.ProtoAnyTLS:
	default:
		return "", fmt.Errorf("unsupported share protocol %s", n.Proto)
	}
	link := url.URL{Scheme: n.Proto, User: url.User(credential), Host: address, RawQuery: q.Encode(), Fragment: e.Name()}
	return link.String(), nil
}

// ClientConfig uses the same outbounds as subscriptions, without third-party
// rules. It is used by selftest to probe the selected entry through SOCKS.
func ClientConfig(st *store.Store, u store.User, tag string, port int) (map[string]any, error) {
	eps, _, err := Endpoints(st, u)
	if err != nil {
		return nil, err
	}
	for _, e := range eps {
		if e.Node.Tag != tag {
			continue
		}
		ob, ok := singboxOutbound(e)
		if !ok {
			return nil, fmt.Errorf("unsupported outbound")
		}
		ob["tag"] = "probe"
		return map[string]any{
			"log":       map[string]any{"level": "error"},
			"inbounds":  []any{map[string]any{"type": "mixed", "listen": "127.0.0.1", "listen_port": port}},
			"outbounds": []any{ob},
			"dns":       map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}}},
			"route":     map[string]any{"final": "probe", "default_domain_resolver": "local"},
		}, nil
	}
	return nil, fmt.Errorf("user has no usable entry for %s", tag)
}
