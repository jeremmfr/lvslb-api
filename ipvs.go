package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"github.com/gorilla/mux"
)

// listIpvsAll : return output of command ipvsadm -L -n
func listIpvsAll(w http.ResponseWriter, r *http.Request) {
	stdout, err := exec.Command("ipvsadm", "-L", "-n").Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintln(w, string(stdout))
}

// listIpvs : return output of command ipvsadm -L -n or ipvsadm -Z for specific virtual_server
func listIpvs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var command []string

	if r.URL.Query().Get("zero") == trueStr {
		command = append(command, "-Z")
	} else {
		command = append(command, "-L", "-n")
	}

	switch strings.ToLower(vars["proto"]) {
	case "tcp":
		command = append(command, "-t")
	case "udp":
		command = append(command, "-u")
	default:
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Unknown Protocol")
		return
	}
	if strings.Contains(vars["IP"], ":") {
		command = append(command, strings.Join([]string{"[", vars["IP"], "]", ":", vars["port"]}, ""))
	} else {
		command = append(command, strings.Join([]string{vars["IP"], ":", vars["port"]}, ""))
	}
	if r.URL.Query().Get("stats") == trueStr && r.URL.Query().Get("zero") == "" {
		command = append(command, "--stats", "--exact")
	}
	stdout, err := exec.Command("ipvsadm", command...).Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if r.URL.Query().Get("count") == trueStr {
		realServer := strings.Count(string(stdout), ">")
		if realServer == 0 {
			fmt.Fprintln(w, "Unknown virtual_server")
		} else {
			fmt.Fprintln(w, realServer-1, "real_server(s)")
		}
	}
	fmt.Fprintln(w, string(stdout))
}
