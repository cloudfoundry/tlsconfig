package tlsconfig_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/pivotal-cf/tlsconfig"
	"github.com/pivotal-cf/tlsconfig/certtest"
)

func TestE2E(t *testing.T) {
	t.Parallel()

	ca, err := certtest.BuildCA("tlsconfig")
	if err != nil {
		t.Fatalf("failed to build CA: %v", err)
	}

	pool, err := ca.CertPool()
	if err != nil {
		t.Fatalf("failed to get CA cert pool: %v", err)
	}

	serverCrt, err := ca.BuildSignedCertificate("server")
	if err != nil {
		t.Fatalf("failed to make server certificate: %v", err)
	}
	serverTLSCrt, err := serverCrt.TLSCertificate()
	if err != nil {
		t.Fatalf("failed to get tls server certificate: %v", err)
	}

	clientCrt, err := ca.BuildSignedCertificate("client")
	if err != nil {
		t.Fatalf("failed to make client certificate: %v", err)
	}
	clientTLSCrt, err := clientCrt.TLSCertificate()
	if err != nil {
		t.Fatalf("failed to get tls client certificate: %v", err)
	}

	// Typically we would share a base configuration but here we're pretending
	// to be two different services.
	serverConf := tlsconfig.Build(
		tlsconfig.WithIdentity(serverTLSCrt),
	).Server(
		tlsconfig.WithClientAuthentication(pool),
	)

	clientConf := tlsconfig.Build(
		tlsconfig.WithIdentity(clientTLSCrt),
	).Client(
		tlsconfig.WithAuthority(pool),
	)

	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello, world!")
	}))
	s.TLS = serverConf
	s.StartTLS()
	defer s.Close()

	transport := &http.Transport{TLSClientConfig: clientConf}
	client := &http.Client{Transport: transport}

	res, err := client.Get(s.URL)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	res.Body.Close()

	if have, want := bs, []byte("hello, world!"); !bytes.Equal(have, want) {
		t.Errorf("unexpected body returned; have: %q, want: %q", have, want)
	}
}

func TestInternalDefaults(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	t.Parallel()

	var tcs = []struct {
		name   string
		config *tls.Config
	}{
		{
			name:   "pivotal (client)",
			config: tlsconfig.Build(tlsconfig.WithPivotalDefaults()).Client(),
		},
		{
			name:   "pivotal (server)",
			config: tlsconfig.Build(tlsconfig.WithPivotalDefaults()).Server(),
		},
		{
			name:   "internal (client)",
			config: tlsconfig.Build(tlsconfig.WithInternalServiceDefaults()).Client(),
		},
		{
			name:   "internal (server)",
			config: tlsconfig.Build(tlsconfig.WithInternalServiceDefaults()).Server(),
		},
	}

	for _, tc := range tcs {
		tc := tc // capture variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			config := tc.config

			if have, want := config.PreferServerCipherSuites, true; have != want {
				t.Errorf("expected server cipher suites to be preferred; have: %t", have)
			}

			if have, want := config.MinVersion, uint16(tls.VersionTLS12); have != want {
				t.Errorf("expected TLS 1.2 to be the minimum version; want: %v, have: %v", want, have)
			}

			wantSuites := []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			}
			if have, want := config.CipherSuites, wantSuites; !reflect.DeepEqual(have, want) {
				t.Errorf("expected a different set of ciphersuites; want: %v, have: %v", want, have)
			}

			h2Ciphersuite := tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			if !contains(config.CipherSuites, h2Ciphersuite) {
				// https://http2.github.io/http2-spec/#rfc.section.9.2.2
				t.Errorf("expected the http2 required ciphersuite (%v) to be present; have: %v", h2Ciphersuite, config.CipherSuites)
			}

			wantCurves := []tls.CurveID{tls.CurveP384, tls.CurveP256}
			if have, want := config.CurvePreferences, wantCurves; !reflect.DeepEqual(have, want) {
				t.Errorf("expected a different set of curve preferences; want: %v, have: %v", want, have)
			}
		})
	}
}

func contains(haystack []uint16, needle uint16) bool {
	for _, e := range haystack {
		if e == needle {
			return true
		}
	}

	return false
}
