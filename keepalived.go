package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	auth "github.com/abbot/go-http-auth"
	"github.com/gorilla/mux"
)

// jsonDataValidate validate missing or incompatibility parameters
func jsonDataValidate(ipvs ipvsStruc) string {
	_, _, err := net.ParseCIDR(strings.Join([]string{ipvs.IP, "/32"}, ""))
	if err != nil {
		_, _, err := net.ParseCIDR(strings.Join([]string{ipvs.IP, "/128"}, ""))
		if err != nil {
			return strings.Join([]string{"Error IP LB : ", ipvs.IP}, "")
		}
	}
	portInt, err := strconv.Atoi(ipvs.Port)
	if err != nil {
		return strings.Join([]string{"Error Port LB : ", ipvs.Port}, "")
	}
	if portInt < 0 || portInt > 65535 {
		return strings.Join([]string{"Error Port LB : ", ipvs.Port}, "")
	}
	if ipvs.SorryIP != "" {
		_, _, err := net.ParseCIDR(strings.Join([]string{ipvs.SorryIP, "/32"}, ""))
		if err != nil {
			_, _, err := net.ParseCIDR(strings.Join([]string{ipvs.SorryIP, "/128"}, ""))
			if err != nil {
				return strings.Join([]string{"Error IP sorry server ", ipvs.SorryIP, " not IPv4"}, "")
			}
		}
	}
	if ipvs.Protocol != "TCP" &&
		ipvs.Protocol != "UDP" &&
		ipvs.Protocol != "SCTP" {
		return strings.Join([]string{"Error unknown Protocol :", ipvs.Protocol}, "")
	}
	if ipvs.LbAlgo != "rr" &&
		ipvs.LbAlgo != "wrr" &&
		ipvs.LbAlgo != "lc" &&
		ipvs.LbAlgo != "wlc" &&
		ipvs.LbAlgo != "lblc" &&
		ipvs.LbAlgo != "sh" &&
		ipvs.LbAlgo != "dh" {
		return strings.Join([]string{"Error unknown Lb_algo :", ipvs.LbAlgo}, "")
	}
	if ipvs.LbKind != "NAT" &&
		ipvs.LbKind != "DR" &&
		ipvs.LbKind != "TUN" {
		return strings.Join([]string{"Error unknown Lb_kind :", ipvs.LbKind}, "")
	}
	_, err = strconv.Atoi(ipvs.PersistenceTimeout)
	if err != nil {
		return strings.Join([]string{"Error persistence_timeout ", ipvs.PersistenceTimeout, " not integer"}, "")
	}
	_, err = strconv.Atoi(ipvs.DelayLoop)
	if err != nil {
		return strings.Join([]string{"Error delay_loop ", ipvs.DelayLoop, " not integer"}, "")
	}
	for _, backend := range ipvs.Backends {
		response := jsonDataValidateBackend(backend)
		if response != "" {
			return response
		}
	}
	return ""
}

// jsonDataValidateBackend validate backend in json
func jsonDataValidateBackend(backend ipvsBackend) string {
	_, _, err := net.ParseCIDR(strings.Join([]string{backend.IP, "/32"}, ""))
	if err != nil {
		_, _, err := net.ParseCIDR(strings.Join([]string{backend.IP, "/128"}, ""))
		if err != nil {
			return strings.Join([]string{"Error IP ", backend.IP, " not IPv4 or IPv6"}, "")
		}
	}

	if backend.Port != "" {
		portInt, err := strconv.Atoi(backend.Port)
		if err != nil {
			return strings.Join([]string{"Error Port ", backend.Port, " not integer"}, "")
		}
		if portInt < 0 || portInt > 65535 {
			return strings.Join([]string{"Error Port ", backend.Port, " not in range of port"}, "")
		}
	}
	if backend.Weight != "" {
		_, err = strconv.Atoi(backend.Weight)
		if err != nil {
			return strings.Join([]string{"Error Weight ", backend.Weight, " not integer"}, "")
		}
	}
	if backend.CheckType != checkTCP &&
		backend.CheckType != checkGET &&
		backend.CheckType != checkSSLGET &&
		backend.CheckType != checkMISC &&
		backend.CheckType != checkNONE {
		return strings.Join([]string{"Error unknown check : ", backend.CheckType}, "")
	}
	if backend.CheckPort != "" {
		checkportInt, err := strconv.Atoi(backend.CheckPort)
		if err != nil {
			return strings.Join([]string{"Error Check port ", backend.CheckPort, " not integer"}, "")
		}
		if checkportInt < 1 || checkportInt > 65535 {
			return strings.Join([]string{"Error Check port ", backend.CheckPort, " not in range of port"}, "")
		}
	}
	if backend.CheckTimeout != "" {
		_, err = strconv.Atoi(backend.CheckTimeout)
		if err != nil {
			return strings.Join([]string{"Error Check timeout ", backend.CheckTimeout, " not integer"}, "")
		}
	}
	if backend.NbGetRetry != "" {
		_, err = strconv.Atoi(backend.NbGetRetry)
		if err != nil {
			return strings.Join([]string{"Error Nb_get_retry ", backend.NbGetRetry, " not integer"}, "")
		}
	}
	if backend.DelayBeforeRetry != "" {
		_, err = strconv.Atoi(backend.DelayBeforeRetry)
		if err != nil {
			return strings.Join([]string{"Error Delay_before_retry ", backend.DelayBeforeRetry, " not integer"}, "")
		}
	}
	if backend.URLPath != "" && backend.CheckType != checkGET && backend.CheckType != checkSSLGET {
		return "Error url_path with wrong check_type"
	}
	if backend.URLStatusCode != "" {
		urlStatusCodeInt, err := strconv.Atoi(backend.URLStatusCode)
		if err != nil {
			return strings.Join([]string{"Error Status Code ", backend.URLStatusCode, " not integer"}, "")
		}
		if urlStatusCodeInt < 100 || urlStatusCodeInt > 600 {
			return strings.Join([]string{"Error Status Code ", backend.URLStatusCode, " not in range of HTTP code"}, "")
		}
	}
	if backend.CheckType == checkGET && backend.URLPath == "" {
		return strings.Join([]string{"Error missing url_path for HTTP_GET on ", backend.IP, ":", backend.Port}, "")
	}
	if backend.CheckType == checkSSLGET && backend.URLPath == "" {
		return strings.Join([]string{"Error missing url_path for SSL_GET on ", backend.IP, ":", backend.Port}, "")
	}
	if backend.CheckType == checkMISC && backend.MiscPath == "" {
		return strings.Join([]string{"Error missing misc_path for MISC_CHECK on ", backend.IP, ":", backend.Port}, "")
	}
	return ""
}

// addIpvs : check backend exists, add keepalived file, reload service and add monitoring if script set
func addIpvs(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	var ipvs ipvsStruc
	vars := mux.Vars(r)
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&ipvs)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	ipvs.IP = vars["IP"]
	ipvs.Protocol = vars["proto"]
	ipvs.Port = vars["port"]
	sort.Sort(ipvs.Backends)

	validate := jsonDataValidate(ipvs)
	if validate != "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, validate)
		return
	}
	ipvsExists := checkIpvsExists(ipvs)
	if ipvsExists {
		ipvsOk, err := checkIpvsOk(ipvs)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if !ipvsOk {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "ipvs", ipvs.Protocol, " ", ipvs.IP, ":", ipvs.Port, "already exist with different config")
			return
		}
	}
	err = checkBackends(ipvs)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	mutex.Lock()
	err = addIpvsFile(ipvs)
	if err != nil {
		http.Error(w, err.Error(), 500)
		mutex.Unlock()
		return
	}
	err = reloadIpvs()
	if err != nil {
		http.Error(w, err.Error(), 500)
		mutex.Unlock()
		return
	}
	if *scriptMonitoringAdd != "" {
		backendListComma := ""
		for _, backend := range ipvs.Backends {
			backendListComma = strings.Join([]string{backendListComma, backend.IP, ","}, "")
		}
		periodMon := defaultPeriod
		if ipvs.MonPeriod != "" {
			periodMon = ipvs.MonPeriod
		}
		err := exec.Command(*scriptMonitoringAdd, ipvs.Protocol, ipvs.IP, ipvs.Port, strings.TrimSuffix(backendListComma, ","), periodMon).Run()
		if err != nil {
			log.Print("Error mon_add", err)
		}
	}
	sleep()
	mutex.Unlock()

}

// checkIpvs : check keepalived file and compare from json input
func checkIpvs(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	var ipvs ipvsStruc
	vars := mux.Vars(r)
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&ipvs)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	ipvs.IP = vars["IP"]
	ipvs.Protocol = vars["proto"]
	ipvs.Port = vars["port"]
	sort.Sort(ipvs.Backends)

	validate := jsonDataValidate(ipvs)
	if validate != "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, validate)
		return
	}
	ipvsExists := checkIpvsExists(ipvs)
	if ipvsExists {
		ipvsResponse := ipvs
		ipvsOk, err := checkIpvsOk(ipvs)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if !ipvsOk {
			w.WriteHeader(http.StatusPartialContent)
			ipvsResponse.LbAlgo = "?"
			ipvsResponse.LbKind = "?"
			ipvsResponse.Backends = []ipvsBackend{}
		}
		js, err := json.Marshal(ipvsResponse)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(js)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

// removeIpvs : remove keepalived file, reload service and remove monitoring if script set
func removeIpvs(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	var ipvs ipvsStruc
	vars := mux.Vars(r)
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&ipvs)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	ipvs.IP = vars["IP"]
	ipvs.Protocol = vars["proto"]
	ipvs.Port = vars["port"]
	sort.Sort(ipvs.Backends)

	validate := jsonDataValidate(ipvs)
	if validate != "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, validate)
		return
	}
	mutex.Lock()
	ipvsExists := checkIpvsExists(ipvs)
	if ipvsExists {
		err := removeIpvsFile(ipvs)
		if err != nil {
			http.Error(w, err.Error(), 500)
			mutex.Unlock()
			return
		}
	}
	err = reloadIpvs()
	if err != nil {
		http.Error(w, err.Error(), 500)
		mutex.Unlock()
		return
	}
	if *scriptMonitoringRemove != "" {
		backendListComma := ""
		for _, backend := range ipvs.Backends {
			backendListComma = strings.Join([]string{backendListComma, backend.IP, ","}, "")
		}
		periodMon := defaultPeriod
		if ipvs.MonPeriod != "" {
			periodMon = ipvs.MonPeriod
		}
		err := exec.Command(*scriptMonitoringRemove, ipvs.Protocol, ipvs.IP, ipvs.Port, strings.TrimSuffix(backendListComma, ","), periodMon).Run()
		if err != nil {
			log.Print("Error mon_remove", err)
		}
	}
	sleep()
	mutex.Unlock()
}

// changeIpvs : replace keepalived file, reload service and modify monitoring if script set
func changeIpvs(w http.ResponseWriter, r *http.Request) {
	if *htpasswdfile != "" {
		htpasswd := auth.HtpasswdFileProvider(*htpasswdfile)
		authenticator := auth.NewBasicAuthenticator("Basic Realm", htpasswd)
		usercheck := authenticator.CheckAuth(r)
		if usercheck == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	var ipvs ipvsStruc
	vars := mux.Vars(r)
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&ipvs)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	ipvs.IP = vars["IP"]
	ipvs.Protocol = vars["proto"]
	ipvs.Port = vars["port"]
	sort.Sort(ipvs.Backends)

	validate := jsonDataValidate(ipvs)
	if validate != "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, validate)
		return
	}
	ipvsExists := checkIpvsExists(ipvs)
	if !ipvsExists {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Unknown LB : ", ipvs.Protocol, " ", ipvs.IP, ":", ipvs.Port)
		return
	}
	err = checkBackends(ipvs)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	mutex.Lock()
	err = removeIpvsFile(ipvs)
	if err != nil {
		http.Error(w, err.Error(), 500)
		mutex.Unlock()
		return
	}
	err = addIpvsFile(ipvs)
	if err != nil {
		http.Error(w, err.Error(), 500)
		mutex.Unlock()
		return
	}
	err = reloadIpvs()
	if err != nil {
		http.Error(w, err.Error(), 500)
		mutex.Unlock()
		return
	}
	if *scriptMonitoringChange != "" {
		backendListComma := ""
		for _, backend := range ipvs.Backends {
			backendListComma = strings.Join([]string{backendListComma, backend.IP, ","}, "")
		}
		periodMon := defaultPeriod
		if ipvs.MonPeriod != "" {
			periodMon = ipvs.MonPeriod
		}
		err := exec.Command(*scriptMonitoringChange, ipvs.Protocol, ipvs.IP, ipvs.Port, strings.TrimSuffix(backendListComma, ","), periodMon).Run()
		if err != nil {
			log.Print("Error mon_change", err)
		}
	}
	sleep()
	mutex.Unlock()

}

// reloadIpvs : reload keepalived service
func reloadIpvs() error {
	reloadKeepalivedCommandParts := strings.Fields(*reloadKeepalivedCommand)
	reloadKeepalivedCommandBin := reloadKeepalivedCommandParts[0]
	reloadKeepalivedCommandArgs := reloadKeepalivedCommandParts[1:]
	cmdOut, err := exec.Command(reloadKeepalivedCommandBin, reloadKeepalivedCommandArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf(string(cmdOut), err.Error())
	}
	return nil
}

// checkBackends : check if communication with backends is possible
func checkBackends(ipvs ipvsStruc) error {
	for _, backend := range ipvs.Backends {
		if backend.CheckType != checkNONE {
			switch {
			case backend.CheckPort != "":
				if strings.Contains(backend.IP, ":") {
					conn, err := net.Dial("tcp", strings.Join([]string{"[", backend.IP, "]:", backend.CheckPort}, ""))
					if err != nil {
						return fmt.Errorf("backend unreachable %v:%v", backend.IP, backend.CheckPort)
					}
					defer conn.Close()
				} else {
					conn, err := net.Dial("tcp", strings.Join([]string{backend.IP, ":", backend.CheckPort}, ""))
					if err != nil {
						return fmt.Errorf("backend unreachable %v:%v", backend.IP, backend.CheckPort)
					}
					defer conn.Close()
				}
			case backend.Port != "":
				if strings.Contains(backend.IP, ":") {
					conn, err := net.Dial("tcp", strings.Join([]string{"[", backend.IP, "]:", backend.Port}, ""))
					if err != nil {
						return fmt.Errorf("backend unreachable %v:%v", backend.IP, backend.Port)
					}
					defer conn.Close()
				} else {
					conn, err := net.Dial("tcp", strings.Join([]string{backend.IP, ":", backend.Port}, ""))
					if err != nil {
						return fmt.Errorf("backend unreachable %v:%v", backend.IP, backend.Port)
					}
					defer conn.Close()
				}
			default:
				if strings.Contains(backend.IP, ":") {
					conn, err := net.Dial("tcp", strings.Join([]string{"[", backend.IP, "]:", ipvs.Port}, ""))
					if err != nil {
						return fmt.Errorf("backend unreachable %v:%v", backend.IP, ipvs.Port)
					}
					defer conn.Close()
				} else {
					conn, err := net.Dial("tcp", strings.Join([]string{backend.IP, ":", ipvs.Port}, ""))
					if err != nil {
						return fmt.Errorf("backend unreachable %v:%v", backend.IP, ipvs.Port)
					}
					defer conn.Close()
				}
			}
		}
	}
	return nil
}
