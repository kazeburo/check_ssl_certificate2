package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/jessevdk/go-flags"
)

var version string

const UNKNOWN = 3
const CRITICAL = 2
const WARNING = 1
const OK = 0

type commandOpts struct {
	Timeout      time.Duration `long:"timeout" default:"10s" description:"Timeout to wait for connection"`
	Hostname     string        `short:"H" long:"hostname" description:"IP address or Host name" default:"127.0.0.1"`
	Port         int           `short:"p" long:"port" description:"Port number" default:"443"`
	SNI          string        `long:"sni" description:"sepecify hostname for SNI"`
	VerifySNI    bool          `long:"verify-sni" description:"verify sni hostname"`
	VerifyChains bool          `long:"verify-chains" description:"verify all certificate chains"`
	Crit         int64         `short:"c" long:"critical" default:"14" description:"The critical threshold in days before expiry"`
	TCP4         bool          `short:"4" description:"use tcp4 only"`
	TCP6         bool          `short:"6" description:"use tcp6 only"`
	Version      bool          `short:"v" long:"version" description:"Show version"`
}

func verifyCertificate(opts commandOpts) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	ch := make(chan error, 1)
	start := time.Now()
	certs := make([]*x509.Certificate, 0)
	go func() {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		if opts.SNI != "" {
			tlsConfig.ServerName = opts.SNI
		}
		dialer := &net.Dialer{
			Timeout:   opts.Timeout,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}
		tcpMode := "tcp"
		if opts.TCP4 {
			tcpMode = "tcp4"
		}
		if opts.TCP6 {
			tcpMode = "tcp6"
		}
		conn, err := dialer.DialContext(ctx, tcpMode, net.JoinHostPort(opts.Hostname, fmt.Sprintf("%d", opts.Port)))
		if err != nil {
			ch <- err
			return
		}
		defer conn.Close()
		tlsconn := tls.Client(conn, tlsConfig)
		err = tlsconn.Handshake()
		if err != nil {
			ch <- err
			return
		}
		defer tlsconn.Close()

		certs = tlsconn.ConnectionState().PeerCertificates
		ch <- nil
	}()

	var err error
	select {
	case err = <-ch:
		// nothing
	case <-ctx.Done():
		err = fmt.Errorf("connection or tls handshake timeout")
	}
	if err == nil && len(certs) == 0 {
		err = fmt.Errorf("failed fetch certificate from target host")
	}

	displaySNI := opts.SNI
	if displaySNI == "" {
		displaySNI = "-"
	}
	displayServer := fmt.Sprintf(`%s port %d sni %s`, opts.Hostname, opts.Port, displaySNI)

	if err != nil {
		return "", fmt.Errorf("SSL CERTIFICATE CRITICAL: %v on %s", err, displayServer)
	}

	cert := certs[0]

	if opts.VerifyChains {
		verifyOpts := x509.VerifyOptions{
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
		}
		for _, c := range certs[1:] {
			verifyOpts.Intermediates.AddCert(c)
		}
		verifiedChains, err := certs[0].Verify(verifyOpts)
		if err != nil {
			return "", fmt.Errorf("SSL CERTIFICATE CRITICAL: failed verify chains [%v] on %s", err, displayServer)
		}
		if len(verifiedChains) == 0 {
			return "", fmt.Errorf("SSL CERTIFICATE CRITICAL: failed verify chains [%v] on %s", "no verified chains", displayServer)
		}
	}

	if opts.VerifySNI {
		err := cert.VerifyHostname(opts.SNI)
		if err != nil {
			return "", fmt.Errorf("SSL CERTIFICATE CRITICAL: failed verify hostname [%v] on %s", err, displayServer)
		}
	}

	duration := time.Since(start)

	daysRemain := int64(cert.NotAfter.Sub(time.Now().UTC()).Hours() / 24)
	absRemain := daysRemain
	if absRemain < 0 {
		absRemain = absRemain * -1
	}
	endDate := cert.NotAfter.String()
	if daysRemain < 0 {
		return "", fmt.Errorf("SSL CERTIFICATE CRITICAL: this certificate expired %d day(s) ago. end date is [%s] on %s", absRemain, endDate, displayServer)
	}
	if daysRemain < opts.Crit {
		return "", fmt.Errorf("SSL CERTIFICATE CRITICAL: only %d left for this certificate. end date is [%s] on %s", absRemain, endDate, displayServer)
	}

	okMsg := fmt.Sprintf(
		`SSL CERTIFICATE OK - %d day(s) left for this certificate. end date is [%s] on %s|time=%fs;;;0.000000;%f`,
		absRemain,
		endDate,
		displayServer,
		duration.Seconds(),
		opts.Timeout.Seconds(),
	)

	return okMsg, nil
}

func printVersion() {
	fmt.Printf(`%s Compiler: %s %s`,
		version,
		runtime.Compiler,
		runtime.Version())
}

func main() {
	os.Exit(_main())
}

func _main() int {
	opts := commandOpts{}
	psr := flags.NewParser(&opts, flags.Default)
	_, err := psr.Parse()
	if err != nil {
		os.Exit(UNKNOWN)
	}

	if opts.Version {
		printVersion()
		return OK
	}

	if opts.TCP4 && opts.TCP6 {
		fmt.Printf("Both tcp4 and tcp6 are specified\n")
		return UNKNOWN
	}

	if opts.VerifySNI && opts.SNI == "" {
		fmt.Printf("--sni is required when use --verify-sni\n")
		return UNKNOWN
	}

	msg, err := verifyCertificate(opts)
	if err != nil {
		fmt.Println(err.Error())
		return CRITICAL
	}
	fmt.Println(msg)
	return OK
}
