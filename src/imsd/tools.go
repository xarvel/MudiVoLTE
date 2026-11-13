package main

// Subcommands for the package CLI (mudi-volte):
//
//	mudi-imsd status [FILE]                     service state for humans
//	mudi-imsd missed FILE                       missed calls for humans, newest first
//	mudi-imsd sms [-json] [-n N] SPOOL INBOX    SMS to the SIM, newest first (smslist.go)
//	mudi-imsd -config FILE phone-url LOGIN      phone setup link (QR)
//	mudi-imsd qr [-svg | -png FILE] TEXT        QR code to the terminal, SVG or PNG
//	mudi-imsd version                           build version

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"rsc.io/qr"
)

// version is set by the build: -ldflags "-X main.version=…".
var version = "dev"

func runTool(configPath string, args []string) int {
	switch args[0] {
	case "version":
		fmt.Println(version)
		return 0
	case "status":
		path := (&Config{}).stateFile()
		if len(args) > 1 {
			path = args[1]
		}
		return printStatus(os.Stdout, path, time.Now())
	case "sms":
		return runSMS(args[1:])
	case "missed":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: mudi-imsd missed FILE")
			return 2
		}
		return printMissed(os.Stdout, args[1])
	case "phone-url":
		if len(args) != 2 || configPath == "" {
			fmt.Fprintln(os.Stderr, "usage: mudi-imsd -config FILE phone-url USER")
			return 2
		}
		cfg, err := loadConfig(configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		url, err := phoneProvisionURL(cfg, args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(url)
		return 0
	case "screen-qr":
		return runScreenQR(args[1:])
	case "qr":
		svg := len(args) == 3 && args[1] == "-svg"
		png := len(args) == 4 && args[1] == "-png"
		if len(args) != 2 && !svg && !png {
			fmt.Fprintln(os.Stderr, "usage: mudi-imsd qr [-svg | -png FILE] TEXT")
			return 2
		}
		var err error
		if png {
			var c *qr.Code
			if c, err = qrEncode(args[3]); err == nil {
				c.Scale = 10
				err = os.WriteFile(args[2], c.PNG(), 0o644)
			}
		} else if svg {
			var s string
			if s, err = qrSVG(args[2]); err == nil {
				fmt.Println(s)
			}
		} else {
			err = writeQRTerminal(os.Stdout, args[1])
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown command %q (status | missed | phone-url | qr | screen-qr | version)\n", args[0])
	return 2
}

// printStatus returns 0 when registered, 1 when the service is alive but not
// on the network, 3 when it is not running.
func printStatus(w io.Writer, path string, now time.Time) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(w, "Service: not running")
		return 3
	}
	var s serviceState
	if err := json.Unmarshal(raw, &s); err != nil {
		fmt.Fprintf(w, "Service: unreadable state file %s: %v\n", path, err)
		return 3
	}
	alive := s.PID > 0 && syscall.Kill(s.PID, 0) == nil
	// The daemon keeps since and last_error_at true to its monotonic clock as
	// of each write (state.go). Only the time since the last write is this
	// clock's, and a clock stepped back since then must not make it negative.
	idle := now.Sub(s.UpdatedAt)
	if idle < 0 {
		idle = 0
	}
	ago := func(t time.Time) string {
		d := (s.UpdatedAt.Sub(t) + idle).Round(time.Second)
		if d < time.Minute {
			return d.String()
		}
		return d.Round(time.Minute).String()
	}
	switch {
	case !alive || s.Phase == "stopped":
		fmt.Fprintf(w, "Service: not running (last state %q, %s ago)\n", s.Phase, ago(s.UpdatedAt))
	case s.Registered:
		fmt.Fprintf(w, "Service: online, registered for %s\n", ago(s.Since))
	default:
		fmt.Fprintf(w, "Service: connecting (%s for %s)\n", phaseText(s.Phase), ago(s.Since))
	}
	if s.Number != "" {
		fmt.Fprintf(w, "Number:  %s\n", s.Number)
	}
	if s.Interface != "" {
		rat := s.RAT
		if rat == "" {
			rat = "?"
		}
		fmt.Fprintf(w, "Network: %s, IMS on %s (%s), P-CSCF %s\n", rat, s.Interface, s.Address, strings.Join(s.PCSCF, ", "))
	}
	if len(s.Phones) > 0 {
		names := make([]string, len(s.Phones))
		for i, p := range s.Phones {
			names[i] = p
			if slices.Contains(s.PhonesTLS, p) {
				names[i] += " (encrypted)"
			}
		}
		fmt.Fprintf(w, "Phones:  %s\n", strings.Join(names, ", "))
	} else if alive {
		fmt.Fprintln(w, "Phones:  none registered")
	}
	if s.Restarts > 0 {
		fmt.Fprintf(w, "Restarts of the IMS connection: %d\n", s.Restarts)
	}
	if s.CrashRestarts > 0 {
		fmt.Fprintf(w, "Restarts of the service after a crash: %d in a row\n", s.CrashRestarts)
	}
	if s.LastError != "" && s.LastErrorAt != nil {
		fmt.Fprintf(w, "Last error (%s ago): %s\n", ago(*s.LastErrorAt), s.LastError)
	}
	switch {
	case !alive:
		return 3
	case s.Registered:
		return 0
	}
	return 1
}

func phaseText(p string) string {
	switch p {
	case "starting":
		return "starting"
	case "modem":
		return "waiting for the modem and LTE"
	case "pdn":
		return "opening the IMS connection"
	case "registering":
		return "registering with the operator"
	case "recovering":
		return "recovering after a failure"
	case "radio-restart":
		return "restarting the radio"
	}
	return p
}
