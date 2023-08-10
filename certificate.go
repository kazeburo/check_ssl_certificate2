package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

type Opt struct {
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

func (opt *Opt) Verify() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opt.Timeout)
	defer cancel()
	ch := make(chan error, 1)
	start := time.Now()
	certs := make([]*x509.Certificate, 0)
	go func() {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		if opt.SNI != "" {
			tlsConfig.ServerName = opt.SNI
		}
		dialer := &net.Dialer{
			Timeout:   opt.Timeout,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}
		tcpMode := "tcp"
		if opt.TCP4 {
			tcpMode = "tcp4"
		}
		if opt.TCP6 {
			tcpMode = "tcp6"
		}
		conn, err := dialer.DialContext(ctx, tcpMode, net.JoinHostPort(opt.Hostname, fmt.Sprintf("%d", opt.Port)))
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

	displaySNI := opt.SNI
	if displaySNI == "" {
		displaySNI = "-"
	}
	displayServer := fmt.Sprintf(`%s port %d sni %s`, opt.Hostname, opt.Port, displaySNI)

	if err != nil {
		return "", fmt.Errorf("SSL CERTIFICATE CRITICAL: %v on %s", err, displayServer)
	}

	cert := certs[0]

	if opt.VerifyChains {
		verifyOpt := x509.VerifyOptions{
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
		}
		for _, c := range certs[1:] {
			verifyOpt.Intermediates.AddCert(c)
		}
		verifiedChains, err := certs[0].Verify(verifyOpt)
		if err != nil {
			return "", fmt.Errorf("SSL CERTIFICATE CRITICAL: failed verify chains [%v] on %s", err, displayServer)
		}
		if len(verifiedChains) == 0 {
			return "", fmt.Errorf("SSL CERTIFICATE CRITICAL: failed verify chains [%v] on %s", "no verified chains", displayServer)
		}
	}

	if opt.VerifySNI {
		err := cert.VerifyHostname(opt.SNI)
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
	if daysRemain < opt.Crit {
		return "", fmt.Errorf("SSL CERTIFICATE CRITICAL: only %d left for this certificate. end date is [%s] on %s", absRemain, endDate, displayServer)
	}

	okMsg := fmt.Sprintf(
		`SSL CERTIFICATE OK - %d day(s) left for this certificate. end date is [%s] on %s|time=%fs;;;0.000000;%f`,
		absRemain,
		endDate,
		displayServer,
		duration.Seconds(),
		opt.Timeout.Seconds(),
	)

	return okMsg, nil
}
