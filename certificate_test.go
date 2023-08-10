package main

import (
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

func TestVerifyOK(t *testing.T) {
	opt := newOpt("badssl.com")
	_, err := opt.Verify()
	assert.NoError(t, err)
}

func TestVerifyExpired(t *testing.T) {
	{
		opt := newOpt("expired.badssl.com")
		_, err := opt.Verify()
		assert.Error(t, err)
	}
}
func TestVerifyWrongHost(t *testing.T) {
	{
		opt := newOpt("wrong.host.badssl.com")
		_, err := opt.Verify()
		assert.NoError(t, err)
	}
	{
		opt := newOpt("wrong.host.badssl.com")
		opt.VerifySNI = true
		_, err := opt.Verify()
		assert.Error(t, err)
	}
}

func TestVerifySelfSigned(t *testing.T) {
	{
		opt := newOpt("self-signed.badssl.com")
		_, err := opt.Verify()
		assert.NoError(t, err)
	}
	{
		opt := newOpt("self-signed.badssl.com")
		opt.VerifyChains = true
		_, err := opt.Verify()
		assert.Error(t, err)
	}
}

func TestVerifyUntrustRoot(t *testing.T) {
	{
		opt := newOpt("untrusted-root.badssl.com")
		_, err := opt.Verify()
		assert.NoError(t, err)
	}
	{
		opt := newOpt("untrusted-root.badssl.com")
		opt.VerifyChains = true
		_, err := opt.Verify()
		assert.Error(t, err)
	}
}
