package main

import (
	"fmt"
	"github.com/patrickhaller/slog"
	"testing"
)

func TestSetup(t *testing.T) {
	readConfig()
	slog.Init(slog.Config{
		File:      "STDERR",
		Debug:     false,
		AuditFile: "/dev/null",
		Prefix:    "DNST",
	})
}

func TestOkNets(t *testing.T) {
	err := checkRemoteIP("10.1.1.1")
	if err != nil {
		t.Error(fmt.Errorf("10.1.1.1 should be allowed: `%v'", err))
	}
}

func TestDNSBL(t *testing.T) {
	// https://tools.ietf.org/html/rfc5782
	if isBlacklisted("127.0.0.1") {
		t.Error(fmt.Errorf("127.0.0.1 should NOT be blacklisted as per rfc 5782"))
	}
	if !isBlacklisted("127.0.0.2") {
		t.Error(fmt.Errorf("127.0.0.2 should be blacklisted as per rfc 5782"))
	}
}
