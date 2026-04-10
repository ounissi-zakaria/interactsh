package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

	client := srv.Client()

	t.Run("GET / serves XSS payload", func(t *testing.T) {
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
		if !strings.Contains(string(body), "//localhost/x/") {
			t.Fatalf("expected XSS payload to contain //localhost/x/, got: %s", string(body)[:200])
		}
		if !strings.Contains(string(body), "/x/") {
			t.Fatalf("expected XSS payload to contain /x/ path")
		}
		if !strings.Contains(string(body), "localStorage") || !strings.Contains(string(body), "sessionStorage") {
			t.Fatalf("expected XSS payload to contain localStorage/sessionStorage")
		}
		t.Logf("XSS payload served correctly (%d bytes)", len(body))
	})

	t.Run("POST /x saves pingback", func(t *testing.T) {
		payload := strings.NewReader(`{"url":"https://victim.com/admin","cookie":"session=abc123","domain":"victim.com","referrer":"https://victim.com/","ua":"Mozilla/5.0","title":"Admin Panel","dom":"<html><head><title>Admin</title></head><body><h1>Admin Dashboard</h1></body></html>","localStorage":{"token":"jwt-abc-123","theme":"dark"},"sessionStorage":{"temp":"data","csrf":"xyz789"}}`)
		resp, err := client.Post(srv.URL+"/x/", "application/json", payload)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		entries, _ := os.ReadDir(xssDir)
		if len(entries) == 0 {
			t.Fatal("expected at least one file in xss dir")
		}

		fileName := entries[0].Name()
		if !strings.HasSuffix(fileName, ".html") {
			t.Fatalf("expected .html file, got %s", fileName)
		}

		content, _ := os.ReadFile(xssDir + "/" + fileName)
		htmlStr := string(content)
		t.Logf("Saved report: %s (%d bytes)", fileName, len(content))

		for _, want := range []string{"XSS Pingback Report", "victim.com", "session=abc123", "Admin Panel", "DOM", "jwt-abc-123", "csrf", "xyz789"} {
			if !strings.Contains(htmlStr, want) {
				t.Errorf("report missing expected string: %s", want)
			}
		}
	})

	t.Run("GET /x/{id} serves report", func(t *testing.T) {
		entries, _ := os.ReadDir(xssDir)
		if len(entries) == 0 {
			t.Fatal("no reports to test")
		}
		id := strings.TrimSuffix(entries[0].Name(), ".html")
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
		payload := strings.NewReader(`{"url":"https://victim.com/secret","cookie":"sid=xyz","domain":"victim.com","ua":"TestBot/1.0","title":"Secret Page","dom":"<html></html>","localStorage":{},"sessionStorage":{}}`)
		resp, err := client.Post(srv.URL+"/x/", "application/json", payload)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		// Wait for async goroutine to send notification
		var webhookPayload *discordWebhookPayload
		for i := 0; i < 50; i++ {
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
		if !strings.Contains(fieldNames["Report"], "/x/") {
			t.Errorf("expected Report to contain /x/, got %s", fieldNames["Report"])
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
