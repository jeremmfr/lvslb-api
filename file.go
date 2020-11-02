package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// checkIpvsExists : test if keepalived file exists.
func checkIpvsExists(ipvs ipvsStruc) bool {
	_, err := os.Stat(strings.Join([]string{*dirKeepalived, ipvs.IP, "_", ipvs.Protocol, "_", ipvs.Port, ".conf"}, ""))

	return !os.IsNotExist(err)
}

// generateFile : generate keepalived file string.
func generateFile(ipvs ipvsStruc) string {
	ipvsIn := strings.Join([]string{"virtual_server ", ipvs.IP, " ", ipvs.Port, " {\n"}, "")
	ipvsIn = strings.Join([]string{ipvsIn, "\tprotocol ", ipvs.Protocol,
		"\n\tlb_kind ", ipvs.LbKind,
		"\n\tlb_algo ", ipvs.LbAlgo, "\n"}, "")
	if ipvs.PersistenceTimeout != "0" {
		ipvsIn = strings.Join([]string{ipvsIn, "\tpersistence_timeout ", ipvs.PersistenceTimeout, "\n"}, "")
	}
	ipvsIn = strings.Join([]string{ipvsIn, "\tdelay_loop ", ipvs.DelayLoop, "\n"}, "")
	if ipvs.Virtualhost != "" {
		ipvsIn = strings.Join([]string{ipvsIn, "\tvirtualhost ", ipvs.Virtualhost, "\n"}, "")
	}
	if ipvs.SorryIP != "" {
		ipvsIn = strings.Join([]string{ipvsIn, "\tsorry_server ", ipvs.SorryIP, " "}, "")
		if ipvs.SorryPort != "" && ipvs.SorryPort != "0" {
			ipvsIn = strings.Join([]string{ipvsIn, ipvs.SorryPort, "\n"}, "")
		} else {
			ipvsIn = strings.Join([]string{ipvsIn, ipvs.Port, "\n"}, "")
		}
	}
	for _, backend := range ipvs.Backends {
		ipvsIn = strings.Join([]string{ipvsIn, "\treal_server ", backend.IP, " "}, "")
		if backend.Port != "" {
			ipvsIn = strings.Join([]string{ipvsIn, backend.Port, " {\n"}, "")
		} else {
			ipvsIn = strings.Join([]string{ipvsIn, ipvs.Port, " {\n"}, "")
		}
		if backend.Weight != "" {
			ipvsIn = strings.Join([]string{ipvsIn, "\t\tweight ", backend.Weight, "\n"}, "")
		} else {
			ipvsIn = strings.Join([]string{ipvsIn, "\t\tweight 1\n"}, "")
		}
		if backend.CheckType != checkNONE {
			ipvsIn = strings.Join([]string{ipvsIn, "\t\t", backend.CheckType, " {\n"}, "")
			if backend.CheckType == checkGET || backend.CheckType == checkSSLGET {
				if backend.URLPath != "" {
					ipvsIn = strings.Join([]string{ipvsIn, "\t\t\turl {\n\t\t\t\tpath ", backend.URLPath, "\n"}, "")
					if backend.URLDigest != "" {
						ipvsIn = strings.Join([]string{ipvsIn, "\t\t\t\tdigest ", backend.URLDigest, "\n"}, "")
					}
					if backend.URLStatusCode != "" {
						ipvsIn = strings.Join([]string{ipvsIn, "\t\t\t\tstatus_code ", backend.URLStatusCode, "\n"}, "")
					}
					ipvsIn = strings.Join([]string{ipvsIn, "\t\t\t}\n"}, "")
				}
			}
			if backend.CheckType == checkGET || backend.CheckType == checkSSLGET || backend.CheckType == checkTCP {
				if backend.CheckPort != "" {
					ipvsIn = strings.Join([]string{ipvsIn, "\t\t\tconnect_port ", backend.CheckPort, "\n"}, "")
				}
				if backend.CheckTimeout != "" {
					ipvsIn = strings.Join([]string{ipvsIn, "\t\t\tconnect_timeout ", backend.CheckTimeout, "\n"}, "")
				}
				if backend.NbGetRetry != "" {
					if backend.CheckType == checkGET || backend.CheckType == checkSSLGET {
						ipvsIn = strings.Join([]string{ipvsIn, "\t\t\tnb_get_retry ", backend.NbGetRetry, "\n"}, "")
					}
					if backend.CheckType == checkTCP {
						ipvsIn = strings.Join([]string{ipvsIn, "\t\t\tretry ", backend.NbGetRetry, "\n"}, "")
					}
				}
				if backend.DelayBeforeRetry != "" {
					ipvsIn = strings.Join([]string{ipvsIn, "\t\t\tdelay_before_retry ", backend.DelayBeforeRetry, "\n"}, "")
				}
			}
			if backend.CheckType == checkMISC {
				if backend.MiscPath != "" {
					ipvsIn = strings.Join([]string{ipvsIn, "\t\t\tmisc_path \"", backend.MiscPath, "\"\n"}, "")
				} else {
					ipvsIn = strings.Join([]string{ipvsIn, "\t\t\tmisc_path \"exit 0\"\n"}, "")
				}
				if backend.CheckTimeout != "" {
					ipvsIn = strings.Join([]string{ipvsIn, "\t\t\tmisc_timeout ", backend.CheckTimeout, "\n"}, "")
				}
			}
			ipvsIn = strings.Join([]string{ipvsIn, "\t\t}\n"}, "")
		}
		ipvsIn = strings.Join([]string{ipvsIn, "\t}\n"}, "")
	}
	ipvsIn = strings.Join([]string{ipvsIn, "}\n"}, "")
	if ipvs.MonPeriod != "" && ipvs.MonPeriod != defaultPeriod {
		ipvsIn = strings.Join([]string{ipvsIn, "# mon_period ", ipvs.MonPeriod, "\n"}, "")
	}

	return ipvsIn
}

// checkIpvsOk : compare keepalived file.
func checkIpvsOk(ipvs ipvsStruc) (bool, error) {
	ipvsIn := generateFile(ipvs)

	ipvsReadByte, err := ioutil.ReadFile(strings.Join([]string{*dirKeepalived,
		ipvs.IP, "_", ipvs.Protocol, "_", ipvs.Port, ".conf"},
		""))
	ipvsRead := string(ipvsReadByte)

	if err != nil {
		return false, fmt.Errorf("failed to read file : %w", err)
	}
	if ipvsIn == ipvsRead {
		return true, nil
	}

	return false, nil
}

// addIpvsFile : write generated keepalived file on system.
func addIpvsFile(ipvs ipvsStruc) error {
	ipvsIn := generateFile(ipvs)
	err := ioutil.WriteFile(strings.Join([]string{*dirKeepalived, // nolint: gosec
		ipvs.IP, "_", ipvs.Protocol, "_", ipvs.Port, ".conf"},
		""), []byte(ipvsIn), 0644)
	if err != nil {
		return fmt.Errorf("failed to write file : %w", err)
	}

	return nil
}

// removeIpvsFile : remove keepalived file.
func removeIpvsFile(ipvs ipvsStruc) error {
	err := os.Remove(strings.Join([]string{*dirKeepalived, ipvs.IP, "_", ipvs.Protocol, "_", ipvs.Port, ".conf"}, ""))
	if err != nil {
		return fmt.Errorf("failed to delete file : %w", err)
	}

	return nil
}
