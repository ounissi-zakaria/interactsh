package server

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

// xssHitsFilename is the JSONL hit log written next to the HTML reports in
// XSSDir. It never ends in .html and the GET /x/{id} handler only serves
// files named <report-id>.html, so the log is unreachable over HTTP.
const xssHitsFilename = "hits.jsonl"

// xssHitRecord is a single summary line appended to hits.jsonl on every
// pingback. Full hit data stays in the HTML report referenced by Report.
type xssHitRecord struct {
	Timestamp  string `json:"timestamp"`
	ID         string `json:"id"`
	Report     string `json:"report"`
	PayloadID  string `json:"payload_id"`
	Host       string `json:"host"`
	RemoteIP   string `json:"remote_ip"`
	URL        string `json:"url"`
	PageDomain string `json:"page_domain"`
	Title      string `json:"title"`
	UserAgent  string `json:"user_agent"`
	Referrer   string `json:"referrer"`
	Cookie     string `json:"cookie"`
}

// newXSSHitRecord builds the JSONL summary for a pingback from the parsed data.
func newXSSHitRecord(data xssPingbackData) xssHitRecord {
	rec := xssHitRecord{
		Timestamp: data.Timestamp,
		ID:        data.ID,
		Report:    data.ID + ".html",
		PayloadID: data.PayloadID,
		Host:      data.Host,
		RemoteIP:  data.RemoteAddress,
	}
	for _, kv := range data.Captured {
		switch kv.Key {
		case "url":
			rec.URL = kv.Value
		case "domain":
			rec.PageDomain = kv.Value
		case "title":
			rec.Title = kv.Value
		case "ua":
			rec.UserAgent = kv.Value
		case "referrer":
			rec.Referrer = kv.Value
		case "cookie":
			rec.Cookie = kv.Value
		}
	}
	return rec
}

// appendXSSHit appends one JSON line to the hits.jsonl log in XSSDir.
//
// Concurrency contract: the whole record INCLUDING the trailing newline is
// emitted with a single Write call. With O_APPEND, a single write(2) is
// atomic w.r.t. other appenders on local filesystems, so concurrent hits
// cannot interleave. Do not refactor into multiple writes per record (e.g.
// an Encoder streaming chunks to the file) without adding a lock.
func (h *HTTPServer) appendXSSHit(rec xssHitRecord) error {
	line, err := jsoniter.Marshal(rec)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(filepath.Join(h.options.XSSDir, xssHitsFilename), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return nil
}

// extractPayloadID derives the payload identifier from the Host header of a
// pingback request. The port is stripped, the longest configured domain suffix
// is removed and the remaining labels are returned joined by '.' (e.g.
// "site1.prod.example.com" with domain "example.com" -> "site1.prod").
// A bare configured domain or an unmatched host yields "".
func extractPayloadID(host string, domains []string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")

	bestDomain := ""
	for _, domain := range domains {
		domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
		if domain == "" || len(domain) <= len(bestDomain) {
			continue
		}
		if host != domain && strings.HasSuffix(host, "."+domain) {
			bestDomain = domain
		}
	}
	if bestDomain == "" {
		return ""
	}
	return strings.TrimSuffix(host, "."+bestDomain)
}

// xssPayloadFor returns the XSS payload served for a given request. The host
// the payload was fetched from is baked in so the pingback POST targets the
// same host, preserving the subdomain as the payload identifier. A custom
// payload (-http-index) may reference the host via a {HOST} placeholder and
// is served untouched if it does not contain one.
func (h *HTTPServer) xssPayloadFor(req *http.Request) string {
	host := req.Host
	if host == "" && len(h.options.Domains) > 0 {
		host = h.options.Domains[0]
	}
	if h.customBanner != "" {
		return strings.ReplaceAll(h.customBanner, "{HOST}", host)
	}
	return strings.Replace(defaultXSSPayload, "XSS_SERVER_DOMAIN", host, 1)
}
