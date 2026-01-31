// main.go
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed" // REQUIRED for //go:embed
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/miekg/dns"
	quic "github.com/quic-go/quic-go"
)

//go:embed webpage/dashboard.html
var dashboardHTML string
var configFileName = filepath.Join(os.Getenv("APPDATA"), "GoDNSForwarder.json")

// Config holds upstream addresses
type Config struct {
	DoHURL       string `json:"doh_url"`    // e.g. https://dns.adguard.com/dns-query
	DoQ          string `json:"doq"`        // e.g. quic://dns.adguard-dns.com
	PreferDoQ    bool   `json:"prefer_doq"` // true = use DoQ if available
	RunAtStartup bool   `json:"run_at_startup"`
}

var (
	cfg   = Config{}
	cfgMu sync.RWMutex

	logs   []string
	logsMu sync.Mutex
)

// appendLog adds a timestamped entry to logs
func appendLog(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	entry := time.Now().Format("2006-01-02 15:04:05") + " " + msg
	logsMu.Lock()
	logs = append([]string{entry}, logs...)
	if len(logs) > 1000 {
		logs = logs[:1000]
	}
	logsMu.Unlock()
	log.Print(msg)
}

// getPrimaryIPv4 returns the first non-loopback IPv4
func getPrimaryIPv4() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, inf := range ifaces {
		if inf.Flags&net.FlagUp == 0 || inf.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := inf.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			return ip.String(), nil
		}
	}
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		if localAddr.IP != nil {
			if ip4 := localAddr.IP.To4(); ip4 != nil {
				return ip4.String(), nil
			}
		}
	}
	return "", errors.New("no non-loopback IPv4 found")
}

// queryDoH sends DNS query via HTTPS DoH
func queryDoH(ctx context.Context, qwire []byte, dohURL string) (*dns.Msg, error) {
	if dohURL == "" {
		return nil, errors.New("DoH URL empty")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", dohURL, bytes.NewReader(qwire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("DoH status %d: %s", resp.StatusCode, string(b))
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return nil, err
	}
	return m, nil
}

// queryDoQ sends DNS query via QUIC DoQ
func queryDoQ(ctx context.Context, qwire []byte, doqURL string) (*dns.Msg, error) {
	if doqURL == "" {
		return nil, errors.New("DoQ host empty")
	}

	// Remove "quic://" prefix if present
	host := strings.TrimPrefix(doqURL, "quic://")
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "853")
	}

	serverName := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		serverName = h
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         serverName,
		NextProtos:         []string{"doq"},
	}
	quicConf := &quic.Config{}

	conn, err := quic.DialAddr(ctx, host, tlsConf, quicConf)
	if err != nil {
		return nil, err
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	if len(qwire) > 0xFFFF {
		return nil, fmt.Errorf("query too large")
	}
	lenBuf := []byte{byte(len(qwire) >> 8), byte(len(qwire) & 0xff)}
	if _, err := stream.Write(append(lenBuf, qwire...)); err != nil {
		return nil, err
	}

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(stream, hdr); err != nil {
		return nil, err
	}
	respLen := int(hdr[0])<<8 | int(hdr[1])
	if respLen <= 0 || respLen > 1<<20 {
		return nil, fmt.Errorf("invalid response length %d", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(stream, resp); err != nil {
		return nil, err
	}

	m := new(dns.Msg)
	if err := m.Unpack(resp); err != nil {
		return nil, err
	}
	return m, nil
}

// serveDNSHandler handles DNS requests
func serveDNSHandler(w dns.ResponseWriter, req *dns.Msg) {
	if req == nil || len(req.Question) == 0 {
		return
	}
	qname := req.Question[0].Name

	qwire, err := req.Pack()
	if err != nil {
		appendLog("pack error: %v", err)
		_ = w.WriteMsg(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})
		return
	}

	cfgMu.RLock()
	dohURL := cfg.DoHURL
	doqURL := cfg.DoQ
	preferDoQ := cfg.PreferDoQ
	cfgMu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	var resp *dns.Msg

	if preferDoQ && doqURL != "" {
		// Primary: DoQ
		resp, err = queryDoQ(ctx, qwire, doqURL)
		if err != nil {
			appendLog("DoQ failed for %s: %v", qname, err)
			// Fallback: DoH
			if dohURL != "" {
				resp, err = queryDoH(ctx, qwire, dohURL)
			}
		}
	} else {
		// Default: DoH
		if dohURL != "" {
			resp, err = queryDoH(ctx, qwire, dohURL)
		} else if doqURL != "" {
			// Optional fallback if DoH is not configured
			resp, err = queryDoQ(ctx, qwire, doqURL)
		}
	}

	if err != nil || resp == nil {
		appendLog("all upstreams failed for %s: %v", qname, err)
		_ = w.WriteMsg(&dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure},
		})
		return
	}

	resp.Id = req.Id
	if err := w.WriteMsg(resp); err != nil {
		appendLog("write response error for %s: %v", qname, err)
	} else {
		appendLog("answered %s via %s", qname,
			func() string {
				if preferDoQ {
					return "DoQ"
				}
				return "DoH"
			}(),
		)
	}

}

func saveConfig() error {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFileName, b, 0644)
}

func loadConfig() error {
	data, err := os.ReadFile(configFileName)
	if err != nil {
		return err
	}
	var loaded Config
	if err := json.Unmarshal(data, &loaded); err != nil {
		return err
	}
	cfgMu.Lock()
	cfg = loaded
	cfgMu.Unlock()
	return nil
}

// simple web UI

func serveWebUI(addr string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})
	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfgMu.RLock()
			_ = json.NewEncoder(w).Encode(cfg)
			cfgMu.RUnlock()
		case http.MethodPost:
			var ncfg Config
			if err := json.NewDecoder(r.Body).Decode(&ncfg); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			cfgMu.Lock()
			oldStartup := cfg.RunAtStartup
			cfg.DoHURL = ncfg.DoHURL
			cfg.DoQ = ncfg.DoQ
			cfg.PreferDoQ = ncfg.PreferDoQ
			cfg.RunAtStartup = ncfg.RunAtStartup
			cfgMu.Unlock()

			if oldStartup != ncfg.RunAtStartup {
				if err := setRunAtStartup(ncfg.RunAtStartup); err != nil {
					appendLog("failed to update startup setting: %v", err)
				}
			}

			if err := saveConfig(); err != nil {
				appendLog("failed to save config: %v", err)
			}

			appendLog(
				"config updated: DoH=%s DoQ=%s PreferDoQ=%v RunAtStartup=%v",
				cfg.DoHURL,
				cfg.DoQ,
				cfg.PreferDoQ,
				cfg.RunAtStartup,
			)
			w.WriteHeader(200)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		logsMu.Lock()
		defer logsMu.Unlock()
		_, _ = w.Write([]byte(strings.Join(logs, "\n")))
	})
	appendLog("web UI starting on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		appendLog("web UI stopped: %v", err)
	}
}

const startupRegPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const startupValueName = "GoDNSForwarder"

func setRunAtStartup(enable bool) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return err
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, startupRegPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	if enable {
		return key.SetStringValue(startupValueName, exePath)
	}
	return key.DeleteValue(startupValueName)
}

func isRunAtStartupEnabled() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, startupRegPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()

	_, _, err = key.GetStringValue(startupValueName)
	return err == nil
}

func main() {
	listenPort := 53
	if p := os.Getenv("LISTEN_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 && v < 65536 {
			listenPort = v
		}
	}

	ip, err := getPrimaryIPv4()
	if err != nil {
		appendLog("could not determine local IP: %v", err)
		appendLog("falling back to 127.0.0.1")
		ip = "127.0.0.1"
	}
	listenAddr := net.JoinHostPort(ip, strconv.Itoa(listenPort))

	// default empty upstreams
	cfgMu.Lock()
	cfg.RunAtStartup = isRunAtStartupEnabled()
	cfg.DoHURL = ""
	cfg.DoQ = ""
	cfg.PreferDoQ = false
	cfgMu.Unlock()

	if err := loadConfig(); err != nil {
		appendLog("no saved config found, using defaults")
	}

	dns.HandleFunc(".", serveDNSHandler)
	udpSrv := &dns.Server{Addr: listenAddr, Net: "udp"}
	tcpSrv := &dns.Server{Addr: listenAddr, Net: "tcp"}

	go func() {
		appendLog("starting DNS UDP server on %s", listenAddr)
		if err := udpSrv.ListenAndServe(); err != nil {
			appendLog("udp server stopped: %v", err)
		}
	}()
	go func() {
		appendLog("starting DNS TCP server on %s", listenAddr)
		if err := tcpSrv.ListenAndServe(); err != nil {
			appendLog("tcp server stopped: %v", err)
		}
	}()

	go serveWebUI("localhost:8080")
	select {}
}
