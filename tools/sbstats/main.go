// sb-stats —— 查询 sing-box v2ray_api 的按用户流量统计。
//
// 为什么需要它：
//  1. sing-box 官方发布版**不编译 v2ray_api**，要用 `-tags with_v2ray_api` 自行构建；
//  2. 即使编进去了，也没有类似 `xray api statsquery` 的命令行；
//  3. Clash API 的 /connections 不含用户字段（实测只有 destinationIP/host 等）。
//
// 所以这里直接实现 V2Ray StatsService 的 gRPC 调用，输出格式与
// `xray api statsquery` 对齐，让面板侧可以复用同一套解析逻辑。
//
// 用法：
//
//	sb-stats --server=127.0.0.1:10085 -pattern user>>>
//	sb-stats --server=127.0.0.1:10085 -pattern user>>> -reset
//
// 输出：
//
//	{"stat":[{"name":"user>>>alice>>>traffic>>>uplink","value":"123"}, ...]}
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
)

// ---------------------------------------------------------------- protobuf 手写编解码
//
// 只用到三条消息，手写比引 protoc 和 sing-box 的 proto 依赖划算得多：
//
//	QueryStatsRequest  { repeated string patterns = 3; bool reset = 2; }
//	QueryStatsResponse { repeated Stat stat = 1; }
//	Stat               { string name = 1; int64 value = 2; }

// rawMessage 承载原始 protobuf 字节，配合 rawCodec 绕过代码生成。
type rawMessage struct{ data []byte }

type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) {
	m, ok := v.(*rawMessage)
	if !ok {
		return nil, fmt.Errorf("rawCodec: 期望 *rawMessage，得到 %T", v)
	}
	return m.data, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	m, ok := v.(*rawMessage)
	if !ok {
		return fmt.Errorf("rawCodec: 期望 *rawMessage，得到 %T", v)
	}
	m.data = append([]byte(nil), data...)
	return nil
}

func (rawCodec) Name() string { return "proto" }

func appendVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

func appendTag(buf []byte, field int, wire int) []byte {
	return appendVarint(buf, uint64(field)<<3|uint64(wire))
}

func appendString(buf []byte, field int, s string) []byte {
	if s == "" {
		return buf
	}
	buf = appendTag(buf, field, 2)
	buf = appendVarint(buf, uint64(len(s)))
	return append(buf, s...)
}

func appendBool(buf []byte, field int, v bool) []byte {
	if !v {
		return buf
	}
	buf = appendTag(buf, field, 0)
	return append(buf, 1)
}

// readVarint 从 data[pos] 读一个 varint，返回值和新的位置。
func readVarint(data []byte, pos int) (uint64, int, error) {
	var value uint64
	var shift uint
	for {
		if pos >= len(data) {
			return 0, pos, fmt.Errorf("varint 越界")
		}
		b := data[pos]
		pos++
		if shift == 63 && b > 1 {
			return 0, pos, fmt.Errorf("varint overflow")
		}
		value |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, pos, nil
		}
		shift += 7
		if shift > 63 {
			return 0, pos, fmt.Errorf("varint 过长")
		}
	}
}

// parseQueryStatsResponse 解出 repeated Stat。
func parseQueryStatsResponse(data []byte) (map[string]int64, error) {
	out := map[string]int64{}
	pos := 0
	for pos < len(data) {
		tag, next, err := readVarint(data, pos)
		if err != nil {
			return out, err
		}
		pos = next
		field, wire := int(tag>>3), int(tag&7)
		if wire != 2 || field != 1 {
			// 跳过不认识的字段
			if wire == 0 {
				_, pos, err = readVarint(data, pos)
				if err != nil {
					return out, err
				}
				continue
			}
			if wire == 2 {
				var length uint64
				length, pos, err = readVarint(data, pos)
				if err != nil {
					return out, err
				}
				if length > uint64(len(data)-pos) {
					return out, fmt.Errorf("field length out of bounds")
				}
				pos += int(length)
				continue
			}
			return out, fmt.Errorf("不支持的 wire type %d", wire)
		}
		var length uint64
		length, pos, err = readVarint(data, pos)
		if err != nil {
			return out, err
		}
		if length > uint64(len(data)-pos) {
			return out, fmt.Errorf("stat 越界")
		}
		name, value, err := parseStat(data[pos : pos+int(length)])
		if err != nil {
			return out, err
		}
		pos += int(length)
		if name != "" {
			out[name] = value
		}
	}
	return out, nil
}

func parseStat(data []byte) (string, int64, error) {
	var name string
	var value int64
	pos := 0
	for pos < len(data) {
		tag, next, err := readVarint(data, pos)
		if err != nil {
			return "", 0, err
		}
		pos = next
		field, wire := int(tag>>3), int(tag&7)
		switch {
		case field == 1 && wire == 2:
			var length uint64
			length, pos, err = readVarint(data, pos)
			if err != nil || length > uint64(len(data)-pos) {
				return "", 0, fmt.Errorf("invalid Stat name length")
			}
			name = string(data[pos : pos+int(length)])
			pos += int(length)
		case field == 2 && wire == 0:
			var raw uint64
			raw, pos, err = readVarint(data, pos)
			if err != nil {
				return "", 0, err
			}
			value = int64(raw)
		default:
			return "", 0, fmt.Errorf("unsupported Stat field")
		}
	}
	return name, value, nil
}

// ---------------------------------------------------------------- 主流程

// stat 是输出给面板的条目，字段名与 `xray api statsquery` 保持一致。
type stat struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type response struct {
	Stat     []stat `json:"stat"`
	Instance string `json:"instance,omitempty"`
}

func main() {
	server := flag.String("server", "127.0.0.1:10085", "v2ray_api 的 gRPC 地址")
	pattern := flag.String("pattern", "", "只返回名字含该前缀的统计（如 user>>>）")
	reset := flag.Bool("reset", false, "读取后清零（不要用于面板正在采集的内核）")
	raw := flag.Bool("json", false, "直接输出原始 JSON（不排序、不带包装）")
	timeout := flag.Duration("timeout", 10*time.Second, "超时")
	flag.Parse()

	codec := rawCodec{}
	encoding.RegisterCodec(codec)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := grpc.NewClient(*server, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "连接 %s 失败: %v\n", *server, err)
		os.Exit(1)
	}
	defer conn.Close()

	// QueryStatsRequest{ pattern, reset }
	req := &rawMessage{}
	req.data = appendString(req.data, 3, *pattern)
	req.data = appendBool(req.data, 2, *reset)

	resp := &rawMessage{}
	var headers metadata.MD
	err = conn.Invoke(ctx,
		"/v2ray.core.app.stats.command.StatsService/QueryStats",
		req, resp, grpc.ForceCodec(codec), grpc.Header(&headers))
	if err != nil {
		fmt.Fprintf(os.Stderr, "QueryStats 失败: %v\n", err)
		fmt.Fprintln(os.Stderr, "提示：sing-box 需要用 -tags with_v2ray_api 编译，且配置里启用 experimental.v2ray_api")
		os.Exit(1)
	}

	values, err := parseQueryStatsResponse(resp.data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析响应失败: %v\n", err)
		os.Exit(1)
	}

	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)

	items := make([]stat, 0, len(names))
	for _, name := range names {
		items = append(items, stat{Name: name, Value: fmt.Sprintf("%d", values[name])})
	}
	if *raw {
		out, err := json.Marshal(values)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(out))
		return
	}

	instance := ""
	if values := headers.Get("vega-stats-instance"); len(values) > 0 {
		instance = values[0]
	}
	out, err := json.Marshal(response{Stat: items, Instance: instance})
	if err != nil {
		fmt.Fprintf(os.Stderr, "序列化失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
