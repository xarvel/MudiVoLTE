package main

// JSON config of the daemon. The defaults suit any operator: the interface,
// the P-CSCF and the IMS PDN profile are discovered on the device (§88:
// CGCONTRDP, CGDCONT); a field in the file overrides the default. The
// mudi-volte package builds this file from UCI (/etc/config/mudi-volte) when
// the service starts.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

type Config struct {
	Mode        string     `json:"mode"`         // check | register-once | daemon | service | sip-test
	Interface   string     `json:"interface"`    // rmnet_data1 | auto
	Allow       []string   `json:"allow"`        // allow-list for incoming calls (E.164); empty = reject everyone
	IncomingAll bool       `json:"incoming_all"` // S7: accept incoming calls from everyone (no allow-list needed)
	SIP         *SIPConfig `json:"sip"`          // S7: SIP bridge for the phones in the LAN; nil = off
	// MaxCallSec, RecordDir and PlayFile are for development without phones
	// (modes daemon and register-once); the package never writes them, and
	// RecordDir and PlayFile do nothing while the sip block is present, as in
	// the service (see package/README.md, "The daemon's own configuration").
	MaxCallSec  int        `json:"max_call_sec"` // >0: hang up every call after N seconds
	RecordDir   string     `json:"record_dir"`   // S4: directory for WAV recordings of the calls answered without the bridge; empty = none
	PlayFile    string     `json:"play_file"`    // S4: WAV (8 or 16 kHz mono PCM16) played into such a call; empty = silence
	SMSInbox    string     `json:"sms_inbox"`    // incoming SMS over IMS (JSON lines, 0600); empty = /root/imsd/sms-inbox.jsonl
	SMS         *SMSConfig `json:"sms"`          // SMS to and from the phones (needs sip); nil = off
	MissedCalls string     `json:"missed_calls"` // incoming calls that no phone answered (JSON lines, 0600); empty = not recorded
	LocalIPv4   string     `json:"local_ipv4"`   // "" | auto | address
	PCSCF       []string   `json:"pcscf"`        // in the order of attempts; empty = auto (CGCONTRDP, §88)
	PCSCFPort   int        `json:"pcscf_port"`   // unprotected P-CSCF port, 5060
	IMEI        string     `json:"imei"`         // "" = auto (CGSN)
	Domain      string     `json:"domain"`       // "" = from the ISIM or derived from the IMSI (TS 23.003 §13)
	SMSC        string     `json:"smsc"`         // "" = from the SIM (EF_SMSP) or from the first incoming message
	Codecs      []string   `json:"codecs"`       // network codecs in order; empty = whatever is linked in
	// LooseInboundSrcPort: do not pin the P-CSCF source port in the inbound
	// IPsec policies (the misbehaving 192.0.2.20, §81–82). On by default.
	LooseInboundSrcPort *bool  `json:"loose_inbound_src_port"`
	LogLevel            string `json:"log_level"`
	LogFile             string `json:"log_file"`        // log to a file as well (rotated to .1); empty = stderr only
	LogFileMaxKB        int    `json:"log_file_max_kb"` // log file limit, KB; 0 = 1024
	// IPsecTool installs the security associations: "" or "netlink" through
	// the kernel's XFRM socket (the keys never pass through a command line),
	// "ip" through iproute2 as before, a fallback should netlink misbehave.
	IPsecTool string `json:"ipsec_tool"`

	// Service mode (S5): the daemon brings up the IMS PDN itself and watches it.
	IMSProfile int    `json:"ims_profile"` // IMS APN profile (cid); 0 = find APN "ims" in CGDCONT, else 2
	DSIHelper  string `json:"dsi_helper"`  // the program that places the data call; empty = /usr/sbin/mudi-dsi-helper
	StateFile  string `json:"state_file"`  // state for mudi-volte status; empty = /var/run/mudi-volte/state.json
	PhonesFile string `json:"phones_file"` // phone registrations across restarts; empty = /var/run/mudi-volte/phones.json
	PushFile   string `json:"push_file"`   // phones' push parameters (lan_push.go); empty = /etc/mudi-volte/push.json
}

func defaultConfig() *Config {
	return &Config{
		Mode:      "check",
		Interface: "auto",
		PCSCFPort: 5060,
	}
}

func (c *Config) stateFile() string {
	if c.StateFile != "" {
		return c.StateFile
	}
	return "/var/run/mudi-volte/state.json"
}

func (c *Config) smsInbox() string {
	if c.SMSInbox != "" {
		return c.SMSInbox
	}
	return "/root/imsd/sms-inbox.jsonl"
}

func (c *Config) phonesFile() string {
	if c.PhonesFile != "" {
		return c.PhonesFile
	}
	return "/var/run/mudi-volte/phones.json"
}

func (c *Config) pushFile() string {
	if c.PushFile != "" {
		return c.PushFile
	}
	return "/etc/mudi-volte/push.json"
}

func (c *Config) dsiHelper() string {
	if c.DSIHelper != "" {
		return c.DSIHelper
	}
	return "/usr/sbin/" + helperProgram
}

// checkIMSProfile checks ims_profile: 0 to find it, else a profile number the
// DSI library can take (it keeps one byte of it).
func (c *Config) checkIMSProfile() error {
	if p := c.IMSProfile; p < 0 || p > 255 {
		return fmt.Errorf("ims_profile %d is not a modem profile number (1 to 255, or 0 to find it)", p)
	}
	return nil
}

func loadConfig(path string) (*Config, error) {
	cfg := defaultConfig()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) looseSrcPort() bool { return c.LooseInboundSrcPort == nil || *c.LooseInboundSrcPort }

// pcscfIPs returns the P-CSCF list from the config (no "auto" logic: empty → nil).
func (c *Config) pcscfIPs() []net.IP {
	var ips []net.IP
	for _, s := range c.PCSCF {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}
