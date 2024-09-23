//go:build customcert

package ias

import (
	"encoding/hex"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
)

const vscRelayingCA = `-----BEGIN CERTIFICATE-----
MIIF7TCCA9WgAwIBAgIUCcO0w1h7y6t4fXTntQcBvqhNSEYwDQYJKoZIhvcNAQEL
BQAwgYQxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJl
cmxpbjEUMBIGA1UECgwLTHVuY0dvYmxpbnMxGDAWBgNVBAMMD2x1bmNnb2JsaW5z
LmNvbTEjMCEGCSqGSIb3DQEJARYUaGVscEBsdW5jZ29ibGlucy5jb20wIBcNMjQw
OTE2MDcyNDU0WhgPMjA1NDA5MDkwNzI0NTRaMIGEMQswCQYDVQQGEwJERTEPMA0G
A1UECAwGQmVybGluMQ8wDQYDVQQHDAZCZXJsaW4xFDASBgNVBAoMC0x1bmNHb2Js
aW5zMRgwFgYDVQQDDA9sdW5jZ29ibGlucy5jb20xIzAhBgkqhkiG9w0BCQEWFGhl
bHBAbHVuY2dvYmxpbnMuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEA5mjHgDN64ZRKfd0kVDVcr18/Slg3I6WRYYCHLXREFj9kNbkGwG1iiEYt2p/c
pKE1D5i0miP6x9EWu+h4euE/qY9nUwk/2ZmFf3P8HBvKcCxoMI3WGpWCmnH5e5x0
ILi+O+gnqDdxcTJJjaoJm/3IeNxNPZzTyE6KbgH0feDyL3WrFBU2n3yyyYoFqJ6O
2f8FTrEDKj67bV4zfzLOpnzvQ5p/9I0eIFSSz5hUDSkKLp/Z15vwSjGSgrWFEiDf
uvtMxck6K40nhe3KUZV4LYNsC4RYrN5ANpQMwdB2Sh4+42qnYs/N/UUxS3KfGYxf
/SlOhXfVuljCuEFgZhSh1PVXp5nDuz27jlhaHoAzyiW4hAx2kJ5QgqdPfMJudTuA
9Zf+6w5JJAx/OwOmC4Qw+k3yXgkhZsTK8e2eUQiSfvrH47cL5fHBoDrfmvKqyNWV
f8COYgh//o+Nnfs1MBYZPDBAfW3K1ZbjLTod0hVIRS1JUVarvcY18PW9ILsHdFLl
SQZNkUiJuLQtOcVg3ggNxLZm2XEAj1LKdTaopUlda3mLpJEuqx19Homsgds50JXK
eYCPmeYL7VVQg36+HUekK9K5hnMJANhGH6a/+HjD3gvngcNlUCoPYdklrfGjZETy
axwlJmjIfXVXLR5f5iSxkJCOlWdT1yiaNOmESfDBGQYxTJUCAwEAAaNTMFEwHQYD
VR0OBBYEFKsZ+8HeYAABhYeXhBnKnfFicVelMB8GA1UdIwQYMBaAFKsZ+8HeYAAB
hYeXhBnKnfFicVelMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIB
AGXlmGeNImrjKkesS96ZPlVhrVaj9bb/YKpdY60dpadzTjc73riWHZN1dSrI6RVa
iWJhn1Rv4R4OsYmdFsQoUgeQF6UlC6q6nMuANC4jqlIUdIC/XVSbpSbfdiLvpvVP
7JbnN6hk+YjvZj4eVMQm5d4FaLHrCYBbhJcBp7Z/CX5QURelyvqv4CNFVhiU27vl
aZEc9eLF0/3/weLxA22+Yn9vAeBq/mkuUCM1Wv312AKf7WhC7AR3tAuhqxP+iDJf
1nttVGGioWrnchxT05xetiHiVF7zY7WRLzrOXDOOS2nqmHqY9A0y3F1AtaT77TeI
5o6Zmm69iEQTWFCJZnPgLZl7t57vdJD6cVfOUsYgbNScO5Hk3TzY+28JwdUrBT2I
kSS8m/3WQUvFIspR5P2yfsqJC22SUTzny4GH18F4ja+InDaO1XESoPPgMxGNAWzC
omK8Dg/k2ZUZAH2e13yBN3pZOenAERIjdjTdUmgVAXhvXnivnamrWFtC2CBxqRcP
dnDuR5drrM888wTmD1d4tsR8Ia15aUZVjRynPjn8/Oz9uoHluGcobWg8GtPc8yld
WedEPrxe68ifY+5+2R+QSInNQZZlKDEPX7QKqAtoZtNXuakfC1tnpa/oJf10q3qa
+oga0d3vU68ZTbrprd+jLC003CJUNIjEpdJz+amicMUx
-----END CERTIFICATE-----`

func init() {
	cert := ias.CertFromPEM([]byte(vscRelayingCA))
	initFromEnv(cert)
}

func initFromEnv(cert string) {
	pem, err := hex.DecodeString(cert)
	if err != nil {
		panic(err)
	}
	rootCert, _, err := ias.CertFromPEM(pem)
	if err != nil {
		panic(err)
	} else if rootCert == nil {
		panic(fmt.Sprintf("invalid rootCert: %v", cert))
	}
	setRARootCert(rootCert)
}
