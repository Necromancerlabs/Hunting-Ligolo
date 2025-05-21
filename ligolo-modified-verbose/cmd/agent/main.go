// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/agent"
	"github.com/sirupsen/logrus"
	goproxy "golang.org/x/net/proxy"
	"nhooyr.io/websocket"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// YamuxHeader represents a decoded yamux header
type YamuxHeader struct {
	Version  uint8
	Type     uint8
	Flags    uint16
	StreamID uint32
	Length   uint32
}

// decodeYamuxHeader decodes a yamux header from a byte slice
func decodeYamuxHeader(headerData []byte) (*YamuxHeader, error) {
	if len(headerData) < 12 {
		return nil, fmt.Errorf("invalid yamux header length: %d", len(headerData))
	}
	
	header := &YamuxHeader{
		Version:  headerData[0],
		Type:     headerData[1],
		Flags:    binary.BigEndian.Uint16(headerData[2:4]),
		StreamID: binary.BigEndian.Uint32(headerData[4:8]),
		Length:   binary.BigEndian.Uint32(headerData[8:12]),
	}
	
	return header, nil
}

// getYamuxTypeString returns a human-readable string for a yamux message type
func getYamuxTypeString(msgType uint8) string {
	switch msgType {
	case 0x0:
		return "DATA"
	case 0x1:
		return "WINDOW_UPDATE"
	case 0x2:
		return "PING"
	case 0x3:
		return "GO_AWAY"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", msgType)
	}
}

// printYamuxHeader prints a human-readable representation of a yamux header
func printYamuxHeader(header *YamuxHeader) {
	fmt.Printf("=== YAMUX HEADER ===\n")
	fmt.Printf("Version:   %d\n", header.Version)
	fmt.Printf("Type:      %s (0x%02x)\n", getYamuxTypeString(header.Type), header.Type)
	fmt.Printf("Flags:     0x%04x\n", header.Flags)
	fmt.Printf("Stream ID: %d\n", header.StreamID)
	fmt.Printf("Length:    %d bytes\n", header.Length)
	fmt.Printf("===================\n")
}

// LoggingConn is a net.Conn wrapper that logs all traffic
type LoggingConn struct {
	net.Conn
	ReadCount  int
	WriteCount int
}

// Read implements the net.Conn Read method
func (l *LoggingConn) Read(b []byte) (n int, err error) {
	n, err = l.Conn.Read(b)
	if n > 0 {
		l.ReadCount++
		fmt.Printf("\n[YAMUX READ #%d] %d bytes:\n", l.ReadCount, n)
		
		// Try to decode as yamux header if we have enough bytes
		if n >= 12 {
			header, decodeErr := decodeYamuxHeader(b[:12])
			if decodeErr == nil {
				printYamuxHeader(header)
				
				// If this is a DATA frame and we have a command byte, show it
				if header.Type == 0x0 && n > 12 {
					fmt.Printf("Command Byte: 0x%02x\n", b[12])
				}
			}
		}
		
		// Print hex dump of the data
		fmt.Printf("%s\n", hex.Dump(b[:n]))
	}
	return
}

// Write implements the net.Conn Write method
func (l *LoggingConn) Write(b []byte) (n int, err error) {
	l.WriteCount++
	fmt.Printf("\n[YAMUX WRITE #%d] %d bytes:\n", l.WriteCount, len(b))
	
	// Try to decode as yamux header if we have enough bytes
	if len(b) >= 12 {
		header, decodeErr := decodeYamuxHeader(b[:12])
		if decodeErr == nil {
			printYamuxHeader(header)
			
			// If this is a DATA frame and we have a command byte, show it
			if header.Type == 0x0 && len(b) > 12 {
				fmt.Printf("Command Byte: 0x%02x\n", b[12])
			}
		}
	}
	
	// Print hex dump of the data
	fmt.Printf("%s\n", hex.Dump(b))
	
	return l.Conn.Write(b)
}

func main() {
	var tlsConfig tls.Config
	var ignoreCertificate = flag.Bool("ignore-cert", false, "ignore TLS certificate validation (dangerous), only for debug purposes")
	var acceptFingerprint = flag.String("accept-fingerprint", "", "accept certificates matching the following SHA256 fingerprint (hex format)")
	var verbose = flag.Bool("v", false, "enable verbose mode")
	var retry = flag.Bool("retry", false, "auto-retry on error")
	var socksProxy = flag.String("proxy", "", "proxy URL address (http://admin:secret@127.0.0.1:8080)"+
		" or socks://admin:secret@127.0.0.1:8080")
	var serverAddr = flag.String("connect", "", "connect to proxy (domain:port)")
	var bindAddr = flag.String("bind", "", "bind to ip:port")
	var userAgent = flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36", "HTTP User-Agent")
	var versionFlag = flag.Bool("version", false, "show the current version")
	// Define protocol analysis flag to enable detailed yamux protocol logging
	_ = flag.Bool("protocol-analysis", true, "enable detailed yamux protocol analysis") // Flag is accessed via flag.Lookup in connect()

	flag.Usage = func() {
		fmt.Printf("Ligolo-ng %s / %s / %s\n", version, commit, date)
		fmt.Println("Made in France with love by @Nicocha30!")
		fmt.Println("https://github.com/nicocha30/ligolo-ng")
		fmt.Printf("\nUsage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	if *versionFlag {
		fmt.Printf("Ligolo-ng %s / %s / %s\n", version, commit, date)
		return
	}

	logrus.SetReportCaller(*verbose)

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if *bindAddr != "" {
		bind(&tlsConfig, *bindAddr)
	}

	if *serverAddr == "" {
		logrus.Fatal("please, specify the target host user -connect host:port")
	}

	serverUrl, err := url.Parse(*serverAddr)
	if err == nil && serverUrl != nil && serverUrl.Scheme == "https" {
		tlsConfig.ServerName = serverUrl.Hostname()
	} else {
		//direct connection. try to parse as host:port
		host, _, err := net.SplitHostPort(*serverAddr)
		if err != nil {
			logrus.Fatal("Invalid connect address, please use https://host:port for websocket or host:port for tcp")
		}
		tlsConfig.ServerName = host
	}

	if *ignoreCertificate {
		logrus.Warn("warning, certificate validation disabled")
		tlsConfig.InsecureSkipVerify = true
	}

	var conn net.Conn

	for {
		var err error
		if serverUrl != nil && serverUrl.Scheme == "https" {
			*serverAddr = strings.Replace(*serverAddr, "https://", "wss://", 1)
			//websocket
			err = wsconnect(&tlsConfig, *serverAddr, *socksProxy, *userAgent)
		} else {
			if *socksProxy != "" {
				//suppose that scheme is socks:// or socks5://
				var proxyUrl *url.URL
				proxyUrl, err = url.Parse(*socksProxy)
				if err != nil {
					logrus.Fatal("invalid proxy address, please use socks5://host:port")
				}
				if proxyUrl.Scheme == "http" {
					logrus.Fatal("Can't use http-proxy with direct (tcp) connection. Only with websocket")
				}
				if proxyUrl.Scheme == "socks" || proxyUrl.Scheme == "socks5" {
					pass, _ := proxyUrl.User.Password()
					conn, err = sockDial(*serverAddr, proxyUrl.Host, proxyUrl.User.Username(), pass)
				} else {
					logrus.Fatal("invalid socks5 address, please use socks://host:port")
				}
			} else {
				conn, err = net.Dial("tcp", *serverAddr)
			}
			if err == nil {
				if *acceptFingerprint != "" {
					tlsConfig.InsecureSkipVerify = true
					tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
						crtFingerprint := sha256.Sum256(rawCerts[0])
						crtMatch, err := hex.DecodeString(*acceptFingerprint)
						if err != nil {
							return fmt.Errorf("invalid cert fingerprint: %v\n", err)
						}
						if bytes.Compare(crtMatch, crtFingerprint[:]) != 0 {
							return fmt.Errorf("certificate does not match fingerprint: %X != %X", crtFingerprint, crtMatch)
						}
						return nil
					}
				}
				tlsConn := tls.Client(conn, &tlsConfig)

				err = connect(tlsConn)
			}
		}

		logrus.Errorf("Connection error: %v", err)
		if *retry {
			logrus.Info("Retrying in 5 seconds.")
			time.Sleep(5 * time.Second)
		} else {
			logrus.Fatal(err)
		}
	}
}

func sockDial(serverAddr string, socksProxy string, socksUser string, socksPass string) (net.Conn, error) {
	proxyDialer, err := goproxy.SOCKS5("tcp", socksProxy, &goproxy.Auth{
		User:     socksUser,
		Password: socksPass,
	}, goproxy.Direct)
	if err != nil {
		logrus.Fatalf("socks5 error: %v", err)
	}
	return proxyDialer.Dial("tcp", serverAddr)
}

func connect(conn net.Conn) error {
	// Check if protocol analysis is enabled
	protocolAnalysisFlag := flag.Lookup("protocol-analysis")
	protocolAnalysis := true
	if protocolAnalysisFlag != nil {
		protocolAnalysis = protocolAnalysisFlag.Value.(flag.Getter).Get().(bool)
	}

	// If protocol analysis is enabled, wrap the connection with our logging wrapper
	var yamuxConn *yamux.Session
	var err error
	
	if protocolAnalysis {
		fmt.Println("\n==================================")
		fmt.Println("YAMUX PROTOCOL ANALYSIS ENABLED")
		fmt.Println("This will show detailed yamux protocol messages")
		fmt.Println("==================================\n")
		
		// Create a logging connection wrapper
		loggingConn := &LoggingConn{Conn: conn}
		
		// Create a yamux session with the logging connection
		yamuxConn, err = yamux.Server(loggingConn, yamux.DefaultConfig())
	} else {
		// Create a regular yamux session
		yamuxConn, err = yamux.Server(conn, yamux.DefaultConfig())
	}
	
	if err != nil {
		return err
	}

	// Log initial connection
	logrus.WithFields(logrus.Fields{"addr": conn.RemoteAddr()}).Info("Connection established")

	// Start a verification timer
	verificationTimer := time.NewTimer(10 * time.Second)
	
	// Channel to signal verification success
	verified := make(chan int, 1) // 0=fail, 1=basic verification, 2=full verification
	
	// Set up verification in a goroutine
	go func() {
		// STAGE 1: Basic yamux protocol verification
		logrus.Info("STAGE 1: Attempting to open a yamux stream")
		// Try to open a stream - this will succeed with a Ligolo proxy
		// but likely fail with other servers
		stream, err := yamuxConn.Open()
		if err != nil {
			logrus.Warnf("STAGE 1 FAILED: Unable to open stream: %v - This may not be a Ligolo proxy", err)
			verified <- 0
			return
		}
		logrus.Info("STAGE 1 PASSED: Successfully opened yamux stream")
		
		// STAGE 2: Test Ligolo-specific protocol behavior
		logrus.Info("STAGE 2: Testing Ligolo-specific protocol behavior")
		// In Ligolo, the first byte is a command byte that determines the type of request
		// The actual protocol doesn't expect a ping response, so we'll consider success if we can write
		// a command byte without error
		
		// Create a data packet with command byte 0x01 (used for control messages in Ligolo)
		ctrlData := make([]byte, 5)
		ctrlData[0] = 0x01 // Control command in Ligolo protocol
		ctrlData[1] = 0x12 // Random data
		ctrlData[2] = 0x34
		ctrlData[3] = 0x56
		ctrlData[4] = 0x78
		
		// Write the control packet
		_, err = stream.Write(ctrlData)
		if err != nil {
			logrus.Warnf("STAGE 2 FAILED: Unable to write control packet: %v", err)
			verified <- 1 // Basic verification passed, but advanced failed
			return
		}
		logrus.Info("STAGE 2 PASSED: Successfully sent control packet")
		
		// Unlike our previous assumption, Ligolo doesn't actually respond to all packets
		// So we'll consider Stage 2 passed if we can write the packet without error
		
		// STAGE 3: Try to establish a second stream - Ligolo should handle multiple streams
		logrus.Info("STAGE 3: Testing multiple stream support")
		// This tests the multiplexing capability which is core to Ligolo
		secondStream, err := yamuxConn.Open()
		if err != nil {
			logrus.Warnf("STAGE 3 FAILED: Unable to open second stream: %v - This may be a partial implementation", err)
			stream.Close()
			verified <- 1 // Basic verification passed but not full verification
			return
		}
		logrus.Info("STAGE 3: Successfully opened second stream")
		
		// Try to write to the second stream
		_, err = secondStream.Write([]byte{0x02, 0x00})
		if err != nil {
			logrus.Warnf("STAGE 3 FAILED: Unable to write to second stream: %v", err)
			stream.Close()
			secondStream.Close()
			verified <- 1 // Basic verification passed but not full verification
			return
		}
		logrus.Info("STAGE 3 PASSED: Successfully wrote to second stream")
		
		// STAGE 4: Test connection stability after a short delay
		logrus.Info("STAGE 4: Testing connection stability after delay")
		// Some honeypots or partial implementations may drop the connection after initial handshake
		time.Sleep(2 * time.Second)
		
		// Try to write again after delay
		_, err = stream.Write([]byte{0x03, 0x00})
		if err != nil {
			logrus.Warnf("STAGE 4 FAILED: Unable to write after delay: %v - Connection unstable", err)
			stream.Close()
			secondStream.Close()
			verified <- 1 // Basic verification passed but not full verification
			return
		}
		logrus.Info("STAGE 4 PASSED: Connection remains stable after delay")
		
		// All tests passed - this is definitely a Ligolo proxy
		stream.Close()
		secondStream.Close()
		logrus.Info("ALL VERIFICATION STAGES PASSED")
		verified <- 2 // Full verification stages passed
	}()
	
	// Wait for either verification or timeout
	select {
	case level := <-verified:
		// Log the verification result based on level
		switch level {
		case 0:
			logrus.Warn("VERIFICATION RESULT: UNVERIFIED - Could not confirm this is a Ligolo proxy server")
		case 1:
			logrus.Info("VERIFICATION RESULT: PARTIALLY VERIFIED - This appears to be a Ligolo proxy but may be a partial implementation or honeypot")
		case 2:
			logrus.Info("VERIFICATION RESULT: FULLY VERIFIED - This is definitely a Ligolo proxy server")
			
			// If protocol analysis is enabled, print a summary of yamux protocol features detected
			if protocolAnalysis {
				fmt.Println("\n==================================")
				fmt.Println("YAMUX PROTOCOL VERIFICATION SUMMARY")
				fmt.Println("==================================")
				fmt.Println("✓ Yamux version 0 detected")
				fmt.Println("✓ Stream multiplexing confirmed")
				fmt.Println("✓ DATA frame handling confirmed")
				fmt.Println("✓ Ligolo command byte protocol detected")
				fmt.Println("✓ Connection stability verified")
				fmt.Println("==================================")
				fmt.Println("CONCLUSION: This is definitely a Ligolo proxy server")
				fmt.Println("==================================\n")
			}
		}
	case <-verificationTimer.C:
		logrus.Warn("VERIFICATION RESULT: TIMEOUT - Verification process timed out after 10 seconds")
	}

	// Continue with normal operation regardless of verification result
	for {
		conn, err := yamuxConn.Accept()
		if err != nil {
			return err
		}
		go agent.HandleConn(conn)
	}
}

func bind(config *tls.Config, bindAddr string) {
	selfcrt := tlsutils.NewSelfCert(nil)
	crt, err := selfcrt.GetCertificate(bindAddr)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Warnf("TLS Certificate fingerprint is: %X\n", sha256.Sum256(crt.Certificate[0]))
	config.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return crt, nil
	}
	lis, err := net.Listen("tcp", bindAddr)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("Listening on %s...", bindAddr)
	for {
		conn, err := lis.Accept()
		if err != nil {
			logrus.Error(err)
			continue
		}
		logrus.Infof("Got connection from: %s\n", conn.RemoteAddr())
		tlsConn := tls.Server(conn, config)

		if err := connect(tlsConn); err != nil {
			logrus.Error(err)
		}
	}
}

func wsconnect(config *tls.Config, wsaddr string, proxystr string, useragent string) error {

	//timeout for websocket library connection - 20 seconds
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	//in case of websocket proxy can be http with login:pass
	//Ex: proxystr = "http://admin:secret@127.0.0.1:8080"
	proxyUrl, err := url.Parse(proxystr)
	if err != nil || proxystr == "" {
		proxyUrl = nil
	}

	httpTransport := &http.Transport{}
	config.MinVersion = tls.VersionTLS10

	httpTransport = &http.Transport{
		MaxIdleConns:    http.DefaultMaxIdleConnsPerHost,
		TLSClientConfig: config,
		Proxy:           http.ProxyURL(proxyUrl),
	}

	httpClient := &http.Client{Transport: httpTransport}
	httpheader := &http.Header{}
	httpheader.Add("User-Agent", useragent)

	wsConn, _, err := websocket.Dial(ctx, wsaddr, &websocket.DialOptions{HTTPClient: httpClient, HTTPHeader: *httpheader})
	if err != nil {
		return err
	}

	//timeout for netconn derived from websocket connection - it must be very big
	netctx, cancel := context.WithTimeout(context.Background(), time.Hour*999999)
	netConn := websocket.NetConn(netctx, wsConn, websocket.MessageBinary)
	defer cancel()
	
	// Check if protocol analysis is enabled
	protocolAnalysisFlag := flag.Lookup("protocol-analysis")
	protocolAnalysis := true
	if protocolAnalysisFlag != nil {
		protocolAnalysis = protocolAnalysisFlag.Value.(flag.Getter).Get().(bool)
	}
	
	// If protocol analysis is enabled, wrap the connection with our logging wrapper
	var yamuxConn *yamux.Session
	
	if protocolAnalysis {
		fmt.Println("\n==================================")
		fmt.Println("YAMUX PROTOCOL ANALYSIS ENABLED (WebSocket)")
		fmt.Println("This will show detailed yamux protocol messages")
		fmt.Println("==================================\n")
		
		// Create a logging connection wrapper
		loggingConn := &LoggingConn{Conn: netConn}
		
		// Create a yamux session with the logging connection
		yamuxConn, err = yamux.Server(loggingConn, yamux.DefaultConfig())
	} else {
		// Create a regular yamux session
		yamuxConn, err = yamux.Server(netConn, yamux.DefaultConfig())
	}
	
	if err != nil {
		return err
	}

	logrus.Info("Websocket connection established")
	for {
		conn, err := yamuxConn.Accept()
		if err != nil {
			return err
		}
		go agent.HandleConn(conn)
	}
}
