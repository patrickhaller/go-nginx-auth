package main

/*
 Authenticate users for nginx mail
 https://nginx.org/en/docs/mail/ngx_mail_auth_http_module.html
*/

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/patrickhaller/confix"
	"github.com/patrickhaller/go-ldap-client"
	"github.com/patrickhaller/slog"
	"github.com/patrickhaller/toml"
)

// configuration is via TOML
var cfg struct {
	Port                  string
	ImapPort              string
	AuthFailWindowSeconds int
	AuthFailMaxCount      int
	LogFile               string
	AuditFile             string
	Debug                 bool
	DecapitalizeUserNames bool
	StripDomains          bool
	LdapBase              string
	LdapHost              string
	LdapPort              int
	LdapBindDN            string
	LdapBindPassword      string
	LdapUserFilter        string
	LdapGroupFilter       string
	LdapAttributes        []string
	LdapSkipTLS           bool
	LdapUseSSL            bool
	LdapServerName        string
	OkNets                []string
	DNSBlacklists         []string
}

var okNets [](*net.IPNet)

func readConfig() {
	configfile := flag.String("cf", "./cf.toml", "TOML config file")
	flag.Parse()
	if _, err := os.Stat(*configfile); err != nil {
		slog.F("Config file `%s' is inaccessible: %v", *configfile, err)
	}

	if _, err := toml.DecodeFile(*configfile, &cfg); err != nil {
		slog.F("Config file `%s' failed to parse: %v", *configfile, err)
	}

	if cfg.ImapPort == "" {
		slog.F("Config file `%v' has no imap port", *configfile)
	}

	for n := range cfg.OkNets {
		_, cidr, err := net.ParseCIDR(cfg.OkNets[n])
		if err == nil {
			okNets = append(okNets, cidr)
		} else {
			slog.P("failed to parse OkNet `%v'", cfg.OkNets[n])
		}
	}
}

func getLdapMailHost(username, pw string) (bool, string) {
	slog.D("user %s ldap start", username)
	client := ldap.LDAPClient{}
	if err := confix.Confix("Ldap", &cfg, &client); err != nil {
		slog.P("confix failed: `%v'", err)
		return false, ""
	}
	defer client.Close()

	ok, attrs, err := client.Authenticate(username, pw)
	if err != nil {
		slog.P("ldap error authenticating user `%s': %+v", username, err)
		return false, ""
	}
	if ok {
		slog.D("ldap auth success for user: `%s'", username)
		return true, attrs["mailHost"]
	}

	slog.P("ldap auth failed for user `%s'", username)
	return false, ""
}

func isBlacklisted(rip string) bool {
	octets := strings.Split(rip, ".")
	var buf strings.Builder
	for i := len(octets) - 1; i >= 0; i-- {
		buf.WriteString(octets[i])
		buf.WriteString(".")
	}
	qip := buf.String()

	for i := range cfg.DNSBlacklists {
		q := fmt.Sprintf("%s%s", qip, cfg.DNSBlacklists[i])
		slog.D("blacklist query for `%v'", q)
		addrs, _ := net.LookupHost(q)
		if len(addrs) > 0 {
			slog.P("IP is blacklisted `%v' with `%v'", q, addrs)
			return true
		}
	}
	return false
}

func checkRemoteIP(rip string) error {
	if len(rip) == 0 {
		return nil
	}

	ip := net.ParseIP(rip)
	if ip == nil {
		return fmt.Errorf("not a parseable IP: `%v'", rip)
	}

	for n := range okNets {
		if okNets[n].Contains(ip) {
			return nil
		}
	}

	if isBlacklisted(rip) {
		return errors.New("blacklisted")
	}

	return nil
}

func router(w http.ResponseWriter, r *http.Request) {
	w.Header().Del("Date")

	username := r.Header.Get("Auth-User")
	password := r.Header.Get("Auth-Pass")
	remoteip := r.Header.Get("Client-IP")

	fail := func(comment string, logcomment string) {
		slog.P("%v `%v' %s `%s'", remoteip, username, comment, logcomment)
		w.Header().Set("Auth-Status", comment)
		w.Header().Set("Auth-Wait", "3")
	}

	if err := checkRemoteIP(remoteip); err != nil {
		fail(err.Error(), "")
		return
	}

	if username == "" || password == "" {
		fail("Invalid username or password", "zero-length")
		return
	}

	idx := strings.Index(username, "@")
	if cfg.StripDomains == true && idx != -1 {
		username = username[0:idx]
	}

	if cfg.DecapitalizeUserNames == true {
		username = strings.ToLower(username)
	}

	ok, mailHost := getLdapMailHost(username, password)
	if !ok {
		fail("Invalid username or password", "")
		return
	}

	if mailHost == "" {
		fail("No mail host defined", "")
		return
	}

	ipv4, err := net.LookupHost(mailHost)
	if err != nil {
		fail("DNS Temporary Failure", mailHost)
		return
	}

	slog.P("%v `%v' routing user to `%v'", remoteip, username, mailHost)
	w.Header().Set("Auth-Status", "OK")
	w.Header().Set("Auth-Port", cfg.ImapPort)
	w.Header().Set("Auth-Server", ipv4[0])
}

func main() {
	readConfig()
	slog.Init(slog.Config{
		File:      cfg.LogFile,
		Debug:     cfg.Debug,
		AuditFile: cfg.AuditFile,
		Prefix:    "NGXMA",
	})
	slog.D("go-nginx-auth starting up...")

	http.HandleFunc("/auth", router)
	if err := http.ListenAndServe(cfg.Port, nil); err != nil {
		slog.P("Cannot bind `%s': %v", cfg.Port, err)
	}
}
