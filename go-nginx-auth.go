package main

import (
	"flag"
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
}

func readConfig() {
	configfile := flag.String("cf", "/usr/local/etc/go-nginx-auth.toml", "TOML config file")
	flag.Parse()
	if _, err := os.Stat(*configfile); err != nil {
		slog.P("Config file `%s' is inaccessible: %v", *configfile, err)
	}

	if _, err := toml.DecodeFile(*configfile, &cfg); err != nil {
		slog.P("Config file `%s' failed to parse: %v", *configfile, err)
	}
}

func getLdap(username, pw string) (bool, map[string]string) {
	slog.D("user %s ldap start", username)
	client := ldap.LDAPClient{}
	if err := confix.Confix("Ldap", &cfg, &client); err != nil {
		slog.P("confix failed: `%v'", err)
		return false, nil
	}
	defer client.Close()

	ok, attrs, err := client.Authenticate(username, pw)
	if err != nil {
		slog.P("ldap error authenticating user `%s': %+v", username, err)
		return false, nil
	}
	if ok {
		slog.D("ldap auth success for user: `%s'", username)
		return true, attrs
	}

	slog.P("ldap auth failed for user `%s'", username)
	return false, nil
}

func router(w http.ResponseWriter, r *http.Request) {
	w.Header().Del("Date")

	username := r.Header.Get("Auth-User")
	password := r.Header.Get("Auth-Pass")

	if username == "" || password == "" {
		w.Header().Set("Auth-Status", "Invalid username or password")
		return
	}

	if cfg.DecapitalizeUserNames == true {
		username = strings.ToLower(username)
	}

	ok, attrs := getLdap(username, password)
	mailHost := attrs["mailHost"]
	if mailHost == "" {
		slog.P("no mailHost for user %v", username)
		w.Header().Set("Auth-Status", "No mail host defined")
		return
	}

	if !ok {
		w.Header().Set("Auth-Status", "Invalid username or password")
		return
	}

	ipv4, err := net.LookupHost(mailHost)
	if err != nil {
		slog.P("hostname lookup for %v failed", mailHost)
		w.Header().Set("Auth-Status", "DNS Temporary Failure")
		return
	}

	slog.P("routing user %v to host %v", username, mailHost)
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
