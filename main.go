package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type ipvsStruc struct {
	IP                 string          `json:"IP"`
	Port               string          `json:"Port"`
	Protocol           string          `json:"Protocol"`
	DelayLoop          string          `json:"Delay_loop"`
	LbAlgo             string          `json:"Lb_algo"`
	LbKind             string          `json:"Lb_kind"`
	PersistenceTimeout string          `json:"Persistence_timeout"`
	SorryIP            string          `json:"Sorry_IP"`
	SorryPort          string          `json:"Sorry_port"`
	Virtualhost        string          `json:"Virtualhost"`
	MonPeriod          string          `json:"Mon_period"`
	Backends           ipvsBackendList `json:"Backends"`
}

type ipvsBackend struct {
	IP               string `json:"IP"`
	Port             string `json:"Port"`
	Weight           string `json:"Weight"`
	CheckType        string `json:"Check_type"`
	CheckPort        string `json:"Check_port"`
	CheckTimeout     string `json:"Check_timeout"`
	NbGetRetry       string `json:"Nb_get_retry"`
	DelayBeforeRetry string `json:"Delay_before_retry"`
	URLPath          string `json:"Url_path"`
	URLDigest        string `json:"Url_digest"`
	URLStatusCode    string `json:"Url_status_code"`
	MiscPath         string `json:"Misc_path"`
}

type ipvsBackendList []ipvsBackend

const checkNONE string = "NONE"
const checkGET string = "HTTP_GET"
const checkSSLGET string = "SSL_GET"
const checkTCP string = "TCP_CHECK"
const checkMISC string = "MISC_CHECK"
const defaultPeriod string = "default"
const trueStr string = "true"

func (slice ipvsBackendList) Len() int {
	return len(slice)
}

func (slice ipvsBackendList) Less(i, j int) bool {
	return slice[i].IP < slice[j].IP
}

func (slice ipvsBackendList) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

var (
	htpasswdfile            *string
	reloadKeepalivedCommand *string
	dirKeepalived           *string
	timeSleep               *int
	mutex                   = &sync.Mutex{}
	scriptMonitoringAdd     *string
	scriptMonitoringChange  *string
	scriptMonitoringRemove  *string
)

func main() {
	listenIP := flag.String("ip", "127.0.0.1", "listen on IP")
	listenPort := flag.String("port", "8080", "listen on port")
	https := flag.Bool("https", false, "https = true or false")
	cert := flag.String("cert", "", "file of certificat for https")
	key := flag.String("key", "", "file of key for https")
	accessLogFile := flag.String("log", "/var/log/lvslb-api.access.log", "file for access log")
	htpasswdfile = flag.String("htpasswd", "", "htpasswd file for login:password")

	reloadKeepalivedCommand = flag.String("reload_cmd", "service keepalived reload",
		"command for reload ipvs keepalived process")
	dirKeepalived = flag.String("dir_keepalived", "/etc/keepalived/keepalived-ipvs.d/",
		"directory for keepalived files")
	timeSleep = flag.Int("sleep", 5,
		"time for sleep after reload ipvs keepalived")

	scriptMonitoringAdd = flag.String("mon_add", "",
		"script for monitoring add witch arguments $protocol $ip $port $backends $mon_period")
	scriptMonitoringChange = flag.String("mon_change", "",
		"script for monitoring change witch arguments $protocol $ip $port $backends $mon_period")
	scriptMonitoringRemove = flag.String("mon_remove", "",
		"script for monitoring remove witch arguments $protocol $ip $port $backends $mon_period")

	flag.Parse()

	dirinfo, err := os.Stat(*dirKeepalived)
	if err != nil {
		log.Fatalf(strings.Join([]string{"dir_keepalived ", *dirKeepalived, " not exist"}, ""))
	}
	if !dirinfo.IsDir() {
		log.Fatalf(strings.Join([]string{"dir_keepalived ", *dirKeepalived, " not a directory"}, ""))
	}
	*dirKeepalived = strings.TrimSuffix(*dirKeepalived, "/")
	*dirKeepalived = strings.Join([]string{*dirKeepalived, "/"}, "")

	// accesslog file open
	accessLog, err := os.OpenFile(*accessLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open access log: %s", err)
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/list_ipvs_all/", listIpvsAll)
	router.HandleFunc("/list_ipvs/{proto}/{IP}/{port}/", listIpvs)
	router.HandleFunc("/check_ipvs/{proto}/{IP}/{port}/", checkIpvs)
	router.HandleFunc("/add_ipvs/{proto}/{IP}/{port}/", addIpvs)
	router.HandleFunc("/remove_ipvs/{proto}/{IP}/{port}/", removeIpvs)
	router.HandleFunc("/change_ipvs/{proto}/{IP}/{port}/", changeIpvs)

	loggedRouter := handlers.CombinedLoggingHandler(accessLog, router)
	if *https {
		if (*cert == "") || (*key == "") {
			log.Fatalf("HTTPS true but no cert and key defined")
		} else {
			log.Fatal(http.ListenAndServeTLS(strings.Join([]string{*listenIP, ":", *listenPort}, ""), *cert, *key, loggedRouter))
		}
	} else {
		log.Fatal(http.ListenAndServe(strings.Join([]string{*listenIP, ":", *listenPort}, ""), loggedRouter))
	}
}

func sleep() {
	time.Sleep(time.Duration(*timeSleep) * time.Second)
}
