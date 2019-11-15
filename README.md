# lvslb-api
![GitHub release (latest by date)](https://img.shields.io/github/v/release/jeremmfr/lvslb-api)
[![Go Status](https://github.com/jeremmfr/lvslb-api/workflows/Go%20Tests/badge.svg)](https://github.com/jeremmfr/lvslb-api/actions)
[![Lint Status](https://github.com/jeremmfr/lvslb-api/workflows/GolangCI-Lint/badge.svg)](https://github.com/jeremmfr/lvslb-api/actions)
[![GoDoc](https://godoc.org/github.com/jeremmfr/lvslb-api?status.svg)](https://godoc.org/github.com/jeremmfr/lvslb-api)
[![Go Report Card](https://goreportcard.com/badge/github.com/jeremmfr/lvslb-api)](https://goreportcard.com/report/github.com/jeremmfr/lvslb-api)

Create API REST for keepavlived virtual_server (generate file, reload keepalived and ipvs command)

Compile:
--------
export GO111MODULE=on  
go build -o lvslb-api

Run:
----

	 ./lvslb-api -h
	 	Usage of ./lvslb-api:
		-cert string
			file of certificat for https
  		-dir_keepalived string
        		directory for keepalived files (default "/etc/keepalived/keepalived-ipvs.d/")
  		-htpasswd string
        		htpasswd file for login:password
  		-https
        		https = true or false
  		-ip string
        		listen on IP (default "127.0.0.1")
  		-key string
        		file of key for https
  		-log string
        		file for access log (default "/var/log/lvslb-api.access.log")
        -mon_add string
                script for monitoring add witch arguments $protocol $ip $port $backends $mon_period
        -mon_change string
                script for monitoring change witch arguments $protocol $ip $port $backends $mon_period
        -mon_remove string
                script for monitoring remove witch arguments $protocol $ip $port $backends $mon_period
  		-port string
        		listen on port (default "8080")
  		-reload_cmd string
        		command for reload ipvs keepalived process (default "service keepalived reload")
  		-sleep int
        		time for sleep after reload ipvs keepalived (default 5)


***
API List :
---------
**LIST ALL IPVS**
	`/list_ipvs_all/`  
status of all virtual_server ipvs

**LIST ONE IPVS**
	`/list_ipvs/{protocol}/{IP}/{port}/`  
	status for one virtual_server ipvs  
		`?stats=true` for stats instead connections  
		`?zero=true` for reset stats  
		`?count=true` for count real_server in virtual_server pool  

**ADD**
	`/add_ipvs/{proto}/{IP}/{port}/`

**REMOVE**
	`/remove_ipvs/{proto}/{IP}/{port}/`

**CHECK**
	`/check_ipvs/{proto}/{IP}/{port}/`

**MODIFY**
	`/change_ipvs/{proto}/{IP}/{port}/`

All requests need json in body (except LIST) with these parameters :
* **IP** : IP for virtual_server
* **Port** : Port for virtual_server
* **Protocol** : Protocol for virtual_server (TCP|UDP|SCTP)
* **Lb_algo** : Algorithm for load balancing (rr|wrr|lc|wlc|lblc|sh|dh)
* **Lb_kind** : Type of load balancing (NAT|DR|TUN)
* **Persistence_timeout** : Persistence timeout for client sticky to backend
* **Delay_loop** : Timer before each backend check
* **Sorry_IP** : (Optional) IP of sorry server if all backend server is out of pool
* **Sorry_Port** : (Optional) [Default: $Port ] Port of sorry server if all backend server is out of pool
* **[]Backends** : List of backends with this parameters :
	* **IP** : IP of backend
	* **Port** : (Optional) [Default: $Port ] Port of backend
	* **Check_type** : Type of check (TCP_CHECK|HTTP_GET|SSL_GET|MISC_CHECK)
	* **Weight** : (Optional) [Default: 1 ] Weight of backend ratio to total weights
	* **Check_port** : (Optional) [Default: $Backend.Port] Port for check if different of Port
	* **Check_timeout** : (Optional) Timeout for check
	* **Nb_get_retry** : (Optional) Retry before remove backend from the pool
	* **Delay_before_retry** : (Optional) Timer before retry after failure
	* **Url_path** : Url for HTTP_GET and SSL_GET
	* **Url_digest** : (Optional) Digest of response for HTTP_GET and SSL_GET
	* **Url_status_code** : (Optional) HTTP Code of response for HTTP_GET and SSL_GET
	* **Misc_path** : (Optional) Path for MISC_CHECK
