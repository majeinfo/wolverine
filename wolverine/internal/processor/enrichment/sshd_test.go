package enrichment

import (
	"context"
	"testing"

	"wolverine/internal/event"
)

func TestSSHD(t *testing.T) {
	tests := []struct {
		service, msg                     string
		user, ip, action, status, method string
		port                             int
		invalidUser                      bool
	}{
		{"sshd", "Accepted publickey for jd from 192.168.1.10 port 51234 ssh2: RSA SHA256:abc", "jd", "192.168.1.10", "login", "success", "publickey", 51234, false},
		{"sshd-session", "Accepted password for root from 2001:db8::1 port 2222 ssh2", "root", "2001:db8::1", "login", "success", "password", 2222, false},
		{"sshd", "Failed password for root from 10.0.0.5 port 40000 ssh2", "root", "10.0.0.5", "login", "failure", "password", 40000, false},
		{"sshd", "Failed password for invalid user admin from 10.0.0.5 port 40001 ssh2", "admin", "10.0.0.5", "login", "failure", "password", 40001, true},
		{"sshd", "Invalid user oracle from 203.0.113.7 port 5555", "oracle", "203.0.113.7", "login", "failure", "", 5555, true},
		{"sshd", "error: maximum authentication attempts exceeded for root from 10.0.0.5 port 40002 ssh2 [preauth]", "root", "10.0.0.5", "login", "failure", "", 40002, false},
		{"sshd", "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.5  user=root", "root", "10.0.0.5", "login", "failure", "", 0, false},
		{"sshd", "pam_unix(sshd:session): session opened for user jd(uid=1000) by jd(uid=0)", "jd", "", "session_open", "success", "", 0, false},
		{"sshd", "pam_unix(sshd:session): session closed for user jd", "jd", "", "session_close", "success", "", 0, false},
		{"sshd", "Connection closed by authenticating user root 10.0.0.5 port 40003 [preauth]", "root", "10.0.0.5", "disconnect", "failure", "", 40003, false},
		{"sshd", "Connection closed by invalid user test 10.0.0.5 port 40004 [preauth]", "test", "10.0.0.5", "disconnect", "failure", "", 40004, true},
		{"sshd", "Connection closed by 10.0.0.5 port 40005 [preauth]", "", "10.0.0.5", "disconnect", "failure", "", 40005, false},
		{"sshd", "Disconnected from user jd 192.168.1.10 port 51234", "jd", "192.168.1.10", "disconnect", "success", "", 51234, false},
		{"sshd", "Received disconnect from 192.168.1.10 port 51234:11: disconnected by user", "", "192.168.1.10", "disconnect", "success", "", 51234, false},
		{"sshd", "Server listening on 0.0.0.0 port 22.", "", "", "", "", "", 0, false},
		{"cron", "Accepted password for jd from 1.2.3.4 port 1 ssh2", "", "", "", "", "", 0, false},
	}

	for _, tt := range tests {
		ev := &event.Event{Service: tt.service, Message: tt.msg, Fields: map[string]any{}}
		ev, err := SSHD{}.Process(context.Background(), ev)
		if err != nil {
			t.Fatalf("%q: %v", tt.msg, err)
		}
		if ev.Username != tt.user || ev.SourceIP != tt.ip || ev.Action != tt.action || ev.Status != tt.status {
			t.Errorf("%q: got user=%q ip=%q action=%q status=%q, want %q %q %q %q",
				tt.msg, ev.Username, ev.SourceIP, ev.Action, ev.Status, tt.user, tt.ip, tt.action, tt.status)
		}
		if got, _ := ev.Fields["auth_method"].(string); got != tt.method {
			t.Errorf("%q: auth_method=%q, want %q", tt.msg, got, tt.method)
		}
		if got, _ := ev.Fields["source_port"].(int); got != tt.port {
			t.Errorf("%q: source_port=%d, want %d", tt.msg, got, tt.port)
		}
		if got, _ := ev.Fields["invalid_user"].(bool); got != tt.invalidUser {
			t.Errorf("%q: invalid_user=%v, want %v", tt.msg, got, tt.invalidUser)
		}
	}
}
