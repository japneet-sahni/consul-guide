# Getting Started with Consul
## 1. Starting Consul in Dev Mode
#### consul agent -dev --client 0.0.0.0 -bind=10.128.0.5 (bind ip is eth0 interface in ifconfig)
#### consul agent -join 10.128.0.5 -bind 10.128.0.7 --data-dir /path/dir

#### consul members
```sh
Node              Address          Status  Type    Build   Protocol  DC   Segment
consul-server-01  10.128.0.5:8301  alive   server  1.10.1  2         dc1  <all>
consul-client-01  10.128.0.7:8301  alive   client  1.10.1  2         dc1  <default>
```

## 2. Remote Execution 
#### (disabled by default post v0.8, needs to be enabled first for each server/client)
#### consul agent -dev --client 0.0.0.0 -bind=10.128.0.5 -hcl='disable_remote_exec=false'
#### consul exec ping google.com
```sh
consul-server-01: PING google.com (209.85.200.139) 56(84) bytes of data.
consul-server-01: 64 bytes from jl-in-f139.1e100.net (209.85.200.139): icmp_seq=1 ttl=115 time=1.10 ms
consul-server-01:
consul-server-01: 64 bytes from jl-in-f139.1e100.net (209.85.200.139): icmp_seq=2 ttl=115 time=1.13 ms
```

## 3. Configuration Directory
#### consul agent --config-dir=/opt/config
```sh
data_dir =  "/opt/consul"
start_join = ["10.128.0.5"]
bind_addr = "10.128.0.7"
```

## 4. Agent Leave Behavior
#### Graceful Exit : Agent notifies the cluster and is then removed (ctrl +c or killall -s 2 consul)
```sh
^C2021-08-23T00:22:14.391Z [INFO]  agent: Caught: signal=interrupt
2021-08-23T00:22:14.391Z [INFO]  agent: Gracefully shutting down agent...
2021-08-23T00:22:14.391Z [INFO]  agent.client: client starting leave
2021-08-23T00:22:14.763Z [INFO]  agent.client.serf.lan: serf: EventMemberLeave: consul-client-01 10.128.0.7
```

#### Forced Removal : Agent is not removed and DC will detect failure and replication will continously retry (ctrl +c or killall -s 9 consul)

```sh
2021-08-23T00:27:40.825Z [DEBUG] agent.server.memberlist.lan: memberlist: Initiating push/pull sync with: consul-client-01 10.128.0.7:8301
2021-08-23T00:27:41.863Z [DEBUG] agent.server.memberlist.lan: memberlist: Failed ping: consul-client-01 (timeout reached)
2021-08-23T00:27:41.863Z [INFO]  agent.server.memberlist.lan: memberlist: Suspect consul-client-01 has failed, no acks received
2021-08-23T00:27:42.062Z [DEBUG] agent.server.memberlist.lan: memberlist: Failed ping: consul-client-01 (timeout reached)
2021-08-23T00:27:42.163Z [INFO]  agent.server.memberlist.lan: memberlist: Suspect consul-client-01 has failed, no acks received
2021-08-23T00:27:42.163Z [INFO]  agent.server.memberlist.lan: memberlist: Marking consul-client-01 as failed, suspect timeout reached (0 peer confirmations)
2021-08-23T00:27:42.163Z [INFO]  agent.server.serf.lan: serf: EventMemberFailed: consul-client-01 10.128.0.7
2021-08-23T00:27:42.163Z [INFO]  agent.server: member failed, marking health critical: member=consul-client-01
2021-08-23T00:27:42.164Z [DEBUG] agent.http: Request finished: method=GET url=/v1/internal/ui/nodes?dc=dc1&index=202 from=184.147.91.57:52634 latency=3m17.751725134s
2021-08-23T00:27:42.263Z [DEBUG] agent.server.memberlist.lan: memberlist: Failed ping: consul-client-01 (timeout reached)
2021-08-23T00:27:42.464Z [INFO]  agent.server.memberlist.lan: memberlist: Suspect consul-client-01 has failed, no acks received
2021-08-23T00:27:44.199Z [INFO]  agent.server.serf.lan: serf: attempting reconnect to consul-client-01 10.128.0.7:8301
```

## 5. Starting Consul in Server Mode
#### consul agent -server -bootstrap-expect=1 -node=consul-server -bind=10.128.0.5 -client 0.0.0.0 -data-dir=/opt/consul -ui=true

```sh
data_dir =  "/opt/consul"
bind_addr = "10.128.0.5"
client_addr = "0.0.0.0"
bootstrap_expect = 1
node_name = "consul-server"
ui = true
server = true
```

## 6. Systemd file

```sh
[Unit]
Description="HashiCorp Consul - A service mesh solution"
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul.d/consul.hcl

[Service]
Type=notify
User=consul
Group=consul
ExecStart=/usr/bin/consul agent -config-dir=/etc/consul.d/
ExecReload=/bin/kill --signal HUP $MAINPID
KillMode=process
KillSignal=SIGTERM
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

# Service Discovery
## 1. Implementation

#### By default, consul DNS runs on 8600 port and consul service runs on consul server
```sh
[root@consul-server-01 ~]# dig @localhost -p 8600 consul.service.consul SRV

; DiG 9.11.26-RedHat-9.11.26-4.el8_4 <<>> @localhost -p 8600 consul.service.consul SRV
; (2 servers found)
;; global options: +cmd
;; Got answer:
;; HEADER opcode: QUERY, status: NOERROR, id: 30709
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;consul.service.consul.         IN      SRV

;; ANSWER SECTION:
consul.service.consul.  0       IN      SRV     1 1 8300 consul-server.node.dc1.consul.

;; ADDITIONAL SECTION:
consul-server.node.dc1.consul. 0 IN     A       10.128.0.5
consul-server.node.dc1.consul. 0 IN     TXT     "consul-network-segment="

;; Query time: 1 msec
;; SERVER: ::1#8600(::1)
;; WHEN: Mon Aug 23 02:15:13 UTC 2021
;; MSG SIZE  rcvd: 151
```

### 1.1 Registering a service
#### Create a service definition file and place it at /etc/consul.d
```sh
{
  "service": {
    "name": "web",
    "port": 80
  }
}
```
```sh
chown consul.consul web.json
consul validate /etc/consul.d
consul reload
```

### 1.2 Finding a service
#### After this step only node health check would pass, no the service health check.
```sh
[root@consul-server-01 consul.d]# dig @localhost -p 8600 web.service.consul SRV

; DiG 9.11.26-RedHat-9.11.26-4.el8_4 <<>> @localhost -p 8600 web.service.consul SRV
; (2 servers found)
;; global options: +cmd
;; Got answer:
;; HEADER opcode: QUERY, status: NOERROR, id: 32077
;; flags: qr aa rd; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 5
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;web.service.consul.            IN      SRV

;; ANSWER SECTION:
web.service.consul.     0       IN      SRV     1 1 80 consul-client-01.node.dc1.consul.
web.service.consul.     0       IN      SRV     1 1 80 consul-server.node.dc1.consul.

;; ADDITIONAL SECTION:
consul-client-01.node.dc1.consul. 0 IN  A       10.128.0.7
consul-client-01.node.dc1.consul. 0 IN  TXT     "consul-network-segment="
consul-server.node.dc1.consul. 0 IN     A       10.128.0.5
consul-server.node.dc1.consul. 0 IN     TXT     "consul-network-segment="
```

### 1.2 Monitoring a service
#### After this step the service health check should also come into picture based on the health check output (below is a script check using curl)
```sh
{
  "service": {
    "name": "web",
    "port": 80,
    "check": {
        "args": [ "curl", "127.0.0.1"],
        "interval": "10s"
    }
  }
}
```
#### You will get below error, hence need to add enable_local_script_checks = true to consul.hcl and restart the service
```sh
consul reload
Error reloading: Unexpected response code: 500 (Failed reloading services: Failed to register service "web": Scripts are disabled on this agent; to enable, configure 'enable_script_checks' or 'enable_local_script_checks' to true)
```
#### The service health will now start failing because no service is running on port 80. Install nginx and you should see service will start passing
```sh
yum -y install nginx
systemctl start nginx
systemctl enable nginx
```

## 2. Types of health check
### a) Script : Exit code. Status of check (0-passing, 1-warning, others-faling)
### b) HTTP : Status code of HTTP check, 2xx is passing
### c) TCP : Status of port check.

# Dynamic Configuration
## 1. Key-Value Store
### Object size can't be > 512KB
```sh
consul kv put max_memory 512M
consul kv get max_memory
consul kv delete max_memory
```

## 2. Watches
### Checks for changes made to diff consul types like key, keyprefixes, services, nodes, checks, events. If change is deteched an external handler is invoked.

```sh
consul watch -type=key -key=max_memory ./script.sh

### Stop nginx and you will notice one failed check
consul watch -type=checks -state critical
```

## 3. Consul templates
### Not a feature of consul but a different binary altogether. Reads the template file and stores the value in output.txt
```sh
### key.tpl
{{ key "max_memory" }}

### Runs continously
consul-template -template "key.tpl:output.txt"
### Runs once
consul-template -template "key.tpl:output.txt" -once

### Configuration File:
consul {
 address = "127.0.0.1:8500"
}
template {
 source = "/root/template/course.tpl"
 destination = "/root/template/course-newname.txt"
 command = "echo Modified > /root/template/delta.txt"
}
```

## 4. envconsul
### Launch a subprocess with envt. variables populated from consul & vault. envconsul will connect to consul/vault, read data from KV with prefix specified and populates the envt. variables with the same key names.

```sh
envconsul -prefix my-app env
```

# Security
## 1. Consul Connect
- Service mesh feature of consul
- Provides service-2-service connection using MTLS & authoriation
- Sidecar proxiesare deployed along with each service.
- Use *Intentions* to allow/deny requests coming from a specific server

### Pre:Requisite: Selinux to Permissive:
```sh
setenforce 0
nano /etc/selinux/config
systemctl stop consul
```
### Step 1: Configure Nginx
```sh
yum -y install nginx
```
```sh
cd /etc/nginx/conf.d/
nano services.conf
```
```sh
server {
    server_name _;
    listen 8080;
    location / {
         proxy_pass http://127.0.0.1:5000;
}
  }

server {
    server_name _;
    listen 9080;
    root /usr/share/nginx/html/backend-service;
}
```
```sh
cd /usr/share/nginx/html
mkdir backend-service
cd backend-service
echo "Backend Service" > index.html
nginx -t
systemctl start nginx
```

```sh
### Curl output till now. Backend works but frontend fails as proxy is not setup.
[root@consul-server-01 backend-service]# curl http://localhost:9080
Backend Service
[root@consul-server-01 backend-service]# curl http://localhost:8080
<html>
<head><title>502 Bad Gateway</title></head>
<body bgcolor="white">
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx/1.14.1</center>
</body>
</html>
```
### Step 2: Create Service Definition:

Definition for Backend Service:
```sh
cd /tmp
```
```sh
nano backend-service.hcl
```
```sh
service {
  name = "backend-service"
  id = "backend-service"
  port = 9080

  connect {
    sidecar_service {}
  }

  check {
    id       = "backend-service-check"
    http     = "http://localhost:9080"
    method   = "GET"
    interval = "1s"
    timeout  = "1s"
  }
}
```
```sh
consul services register backend-service.hcl
```
```sh
nano frontend-service.hcl
```
```sh
service {
  name = "frontend-service"
  port = 8080

  connect {
    sidecar_service {
      proxy {
        upstreams = [
          {
            destination_name = "backend-service"
            local_bind_port  = 5000
          }
        ]
      }
    }
  }

  check {
    id       = "backend-service-check"
    http     = "http://localhost:8080"
    method   = "GET"
    interval = "1s"
    timeout  = "1s"
  }
}
```
```sh
consul agent -dev --client=0.0.0.0
```
```sh
consul services register frontend-service.hcl
consul services register backend-service.hcl
### Services will registered but will still be failing unless proxies are not run.
```

### Step 3: Start Sidecar Proxy:
```sh
consul connect proxy -sidecar-for frontend-service > /tmp/frontend-service.log &
consul connect proxy -sidecar-for backend-service > /tmp/backend-service.log &
netstat -ntlp
```
### Step 4: Verification:
```sh
curl localhost:8080

[root@consul-server-01 consul.d]# netstat -ntlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      2355/consul         
tcp        0      0 10.128.0.5:8300         0.0.0.0:*               LISTEN      2163/consul         
tcp        0      0 10.128.0.5:8301         0.0.0.0:*               LISTEN      2163/consul         
tcp        0      0 10.128.0.5:8302         0.0.0.0:*               LISTEN      2163/consul         
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      2314/nginx: master  
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      2314/nginx: master  
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1288/sshd           
tcp        0      0 0.0.0.0:9080            0.0.0.0:*               LISTEN      2314/nginx: master  
tcp6       0      0 :::21000                :::*                    LISTEN      2365/consul         
tcp6       0      0 :::21001                :::*                    LISTEN      2355/consul         
tcp6       0      0 :::80                   :::*                    LISTEN      2314/nginx: master  
tcp6       0      0 :::8500                 :::*                    LISTEN      2163/consul         
tcp6       0      0 :::8502                 :::*                    LISTEN      2163/consul         
tcp6       0      0 :::22                   :::*                    LISTEN      1288/sshd           
tcp6       0      0 :::8600                 :::*                    LISTEN      2163/consul         
[root@consul-server-01 consul.d]# 
[root@consul-server-01 consul.d]# curl localhost:8080
Backend Service

```
