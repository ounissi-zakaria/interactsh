package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/projectdiscovery/gologger"
)

type discordWebhookPayload struct {
	Embeds []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title     string         `json:"title"`
	Color     int            `json:"color"`
	Fields    []discordField `json:"fields"`
	Footer    *discordFooter `json:"footer,omitempty"`
	Timestamp string         `json:"timestamp"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type discordFooter struct {
	Text string `json:"text"`
}

const (
	discordEmbedColor    = 0xe94560
	discordMaxFieldValue = 1024
	discordTimeout       = 5 * time.Second
)

func sendDiscordNotification(webhookURL string, data xssPingbackData, req *http.Request) {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}

	reportURL := scheme + "://" + req.Host + "/x/" + data.ID

	var urlVal, domainVal, uaVal, cookieVal, titleVal string
	for _, kv := range data.Captured {
		switch kv.Key {
		case "url":
			urlVal = kv.Value
		case "domain":
			domainVal = kv.Value
		case "ua":
			uaVal = kv.Value
		case "cookie":
			cookieVal = kv.Value
		case "title":
			titleVal = kv.Value
		}
	}

	fields := []discordField{
		{Name: "URL", Value: truncate(urlVal, discordMaxFieldValue), Inline: false},
		{Name: "Report", Value: reportURL, Inline: false},
		{Name: "Domain", Value: truncate(domainVal, discordMaxFieldValue), Inline: true},
		{Name: "Title", Value: truncate(titleVal, discordMaxFieldValue), Inline: true},
		{Name: "Remote IP", Value: data.RemoteAddress, Inline: true},
		{Name: "User Agent", Value: truncate(uaVal, discordMaxFieldValue), Inline: false},
	}

	if cookieVal != "" {
		fields = append(fields, discordField{Name: "Cookies", Value: truncate(cookieVal, discordMaxFieldValue), Inline: false})
	}

	payload := discordWebhookPayload{
		Embeds: []discordEmbed{
			{
				Title:     "XSS Pingback Fired",
				Color:     discordEmbedColor,
				Fields:    fields,
				Timestamp: data.Timestamp,
				Footer: &discordFooter{
					Text: "interactsh-server | " + data.RemoteAddress,
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		gologger.Warning().Msgf("Could not marshal Discord payload: %s\n", err)
		return
	}

	client := &http.Client{Timeout: discordTimeout}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		gologger.Warning().Msgf("Could not send Discord notification: %s\n", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		gologger.Warning().Msgf("Discord webhook returned status %d\n", resp.StatusCode)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
