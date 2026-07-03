package main

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func newOpt(h string) Opt {
	d, _ := time.ParseDuration("10s")
	opt := Opt{
		Hostname: h,
		SNI:      h,
		Timeout:  d,
		Port:     443,
		Crit:     14,
		TCP4:     true,
		TCP6:     false,
	}
	return opt
}

func retryWithVerfy(opt Opt, retry int) (string, error) {
	var err error
	var msg string
	for i := 0; i < retry; i++ {
		msg, err = opt.Verify()
		if err == nil {
			return msg, nil
		}
		// connection reset by peer, retry
		if errors.Is(err, net.ErrClosed) || errors.Is(err, net.ErrWriteToConnected) || strings.Contains(err.Error(), "connection reset by peer") {
			continue
		}
		return msg, err
	}
	return msg, err
}

func TestVerifyOK(t *testing.T) {
	opt := newOpt("badssl.com")
	_, err := retryWithVerfy(opt, 3)
	assert.NoError(t, err)
}

func TestWeakKeyExchange(t *testing.T) {
	opt := newOpt("static-rsa.badssl.com")
	_, err := retryWithVerfy(opt, 3)
	assert.NoError(t, err)
}

func TestVerifyExpired(t *testing.T) {
	{
		opt := newOpt("expired.badssl.com")
		_, err := retryWithVerfy(opt, 3)
		assert.Error(t, err)
	}
}
func TestVerifyWrongHost(t *testing.T) {
	{
		opt := newOpt("wrong.host.badssl.com")
		_, err := retryWithVerfy(opt, 3)
		assert.NoError(t, err)
	}
	{
		opt := newOpt("wrong.host.badssl.com")
		opt.VerifySNI = true
		_, err := retryWithVerfy(opt, 3)
		assert.Error(t, err)
	}
}

func TestVerifySelfSigned(t *testing.T) {
	{
		opt := newOpt("self-signed.badssl.com")
		_, err := retryWithVerfy(opt, 3)
		assert.NoError(t, err)
	}
	{
		opt := newOpt("self-signed.badssl.com")
		opt.VerifyChains = true
		_, err := retryWithVerfy(opt, 3)
		assert.Error(t, err)
	}
}

func TestVerifyUntrustRoot(t *testing.T) {
	{
		opt := newOpt("untrusted-root.badssl.com")
		_, err := retryWithVerfy(opt, 3)
		assert.NoError(t, err)
	}
	{
		opt := newOpt("untrusted-root.badssl.com")
		opt.VerifyChains = true
		_, err := retryWithVerfy(opt, 3)
		assert.Error(t, err)
	}
}
