package usocksd

import (
	"net"
	"testing"
	"time"
)

func TestEmptyConfig(t *testing.T) {
	t.Parallel()

	c := NewConfig()
	if c.Incoming.Port != defaultPort {
		t.Errorf("default port != %d", defaultPort)
	}
	if len(c.Outgoing.Addresses) != 0 {
		t.Error("outgoing.addresses must be empty")
	}
	if !c.allowPort(443) {
		t.Error("port 443 must be allowed")
	}
}

func TestConfig(t *testing.T) {
	t.Parallel()

	c := NewConfig()
	now := time.Now()
	if err := c.Load("test/test1.toml"); err != nil {
		t.Fatal(err)
	}
	if c.Incoming.Port != 1080 {
		t.Error("incoming.port != 1080")
	}
	if len(c.Incoming.Addresses) != 1 {
		t.Error("empty incoming.addresses")
	} else {
		ip1 := net.ParseIP("127.0.0.1")
		if !c.Incoming.Addresses[0].Equal(ip1) {
			t.Error(`c.incoming.addresses != ["127.0.0.1"]`)
		}
	}
	if len(c.Incoming.allowSubnets) == 0 {
		t.Error("empty incoming.allow_from")
	} else {
		if !c.allowIP(net.ParseIP("10.1.32.4")) {
			t.Error("10.1.32.4 is not allowed")
		}
		if !c.allowIP(net.ParseIP("192.168.1.1")) {
			t.Error("192.168.1.1 is not allowed")
		}
		if c.allowIP(net.ParseIP("12.34.56.78")) {
			t.Error("12.34.56.78 shout not be allowed")
		}
	}
	if !c.allowFQDN("www.amazon.com", now) {
		t.Error("www.amazon.com should be allowed")
	}
	if !c.allowFQDN("www.google.com", now) {
		t.Error("www.google.com should be allowed")
	}
	if c.allowFQDN("bad.google.com", now) {
		t.Error("bad.amazon.com should be denied")
	}
	if c.allowFQDN("www.2ch.net", now) {
		t.Error("www.2ch.net should be denied")
	}
	if c.allowPort(25) {
		t.Error("port 25 must not be allowed")
	}
	if !c.allowPort(443) {
		t.Error("port 443 must be allowed")
	}
	if len(c.Outgoing.Addresses) != 1 {
		t.Error("empty outgoing.addresses")
	} else {
		if c.Outgoing.Addresses[0].String() != "12.34.56.78" {
			t.Error("failed to parse 12.34.56.78")
		}
	}
	if c.Outgoing.DNSBLDomain != "zen.spamhaus.org" {
		t.Error(`outgoing.dnsbl_domain != "zen.spamhaus.org"`)
	}
}

func TestConfigFail(t *testing.T) {
	t.Parallel()

	c := NewConfig()
	if err := c.Load("test/test2.toml"); err == nil {
		t.Error("loadConfig should fail for test2.toml")
	}

	// expect type mismatch
	c = NewConfig()
	if err := c.Load("test/test3.toml"); err == nil {
		t.Error("loadConfig should fail for test3.toml")
	}
}

func TestTimedDenySites(t *testing.T) {
	t.Parallel()

	c := NewConfig()
	c.Outgoing.TimedDenySites = []TimedDenySite{
		TimedDenySite{
			Begin:     time.Date(1, 1, 1, 12, 23, 34, 0, time.UTC),
			End:       time.Date(1, 1, 1, 13, 35, 57, 0, time.UTC),
			DenySites: []string{"example.com"},
		},
	}

	if !c.allowFQDN("example.com", time.Date(2000, 8, 23, 12, 23, 33, 0, time.UTC)) {
		t.Error("example.com on 2000-08-23 12:23:33 should be allowed")
	}

	if c.allowFQDN("example.com", time.Date(2000, 8, 23, 12, 23, 34, 0, time.UTC)) {
		t.Error("example.com on 2000-08-23 12:23:34 should be denied")
	}

	if c.allowFQDN("example.com", time.Date(2000, 8, 23, 13, 00, 00, 0, time.UTC)) {
		t.Error("example.com on 2000-08-23 13:00:00 should be denied")
	}

	if c.allowFQDN("example.com", time.Date(2000, 8, 23, 13, 35, 57, 0, time.UTC)) {
		t.Error("example.com on 2000-08-23 13:35:57 should be denied")
	}

	if !c.allowFQDN("example.com", time.Date(2000, 8, 23, 13, 35, 58, 0, time.UTC)) {
		t.Error("example.com on 2000-08-23 13:35:58 should be allowed")
	}
}
