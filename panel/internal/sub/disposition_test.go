package sub

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// FlClash 不读 Profile-Title，只从 Content-Disposition 的 filename* 取订阅名
// （lib/models/profile.dart 的 update() 调 getFileNameForDisposition，
// 实现在 lib/common/request.dart）。取不到就退回 defaultLabel——也就是订阅 URL
// 的域名，表现就是「订阅名怎么变成 hk.xxx 了」。
//
// 这里按 FlClash 的解析方式做一次往返，顺便盯住两个容易踩的点：
// 非 ASCII 必须能被解回来，空格不能被编成 "+"（FlClash 用 Uri.decodeComponent，
// 它不会把 "+" 还原成空格）。
func TestContentDispositionCarriesTitle(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	const title = "定制·HK·Vps Quan"
	if err := st.SetSetting("sub_title", title); err != nil {
		t.Fatal(err)
	}

	h := &handler{st: st, cfg: Config{}}
	token, err := st.SubToken(u.Name)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/clash", "/singbox", "/nowhere", "/ajson"} {
		req := httptest.NewRequest(http.MethodGet, "/sub/"+token+path, nil)
		w := httptest.NewRecorder()
		h.subscription(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d: %s", path, w.Code, w.Body.String())
		}

		raw := w.Header().Get("Content-Disposition")
		if raw == "" {
			t.Fatalf("%s: 没发 Content-Disposition，FlClash 会把订阅名显示成域名", path)
		}
		if !strings.HasPrefix(raw, "attachment;") {
			t.Fatalf("%s: Content-Disposition 应当是 attachment，实际 %q", path, raw)
		}

		star := ""
		for _, part := range strings.Split(raw, ";") {
			if part = strings.TrimSpace(part); strings.HasPrefix(part, "filename*=") {
				star = strings.TrimPrefix(part, "filename*=")
			}
		}
		if star == "" {
			t.Fatalf("%s: 没有 filename*，中文标题取不到: %q", path, raw)
		}
		if strings.Contains(star, "+") {
			t.Fatalf("%s: 空格被编成了 +，FlClash 的 decodeComponent 不会还原它: %q", path, star)
		}
		pieces := strings.SplitN(star, "''", 2)
		if len(pieces) != 2 || pieces[0] != "UTF-8" {
			t.Fatalf("%s: filename* 不是 RFC 5987 的 UTF-8''value 形式: %q", path, star)
		}
		got, err := url.PathUnescape(pieces[1])
		if err != nil {
			t.Fatalf("%s: filename* 解不开: %v", path, err)
		}
		if got != title {
			t.Fatalf("%s: 标题往返后变成 %q，想要 %q", path, got, title)
		}

		// 老客户端只认 ASCII 的 filename，至少得给一个非空、没有引号的值
		if !strings.Contains(raw, `filename="`) {
			t.Fatalf("%s: 缺 ASCII 兜底的 filename: %q", path, raw)
		}
	}
}
