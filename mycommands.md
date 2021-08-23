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
(disabled by default post v0.8, needs to be enabled first for each server/client)
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

### By default, consul DNS runs on 8600 port and consul service runs on consul server
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

#### 1.1 Registering a service
Create a service definition file and place it at /etc/consul.d
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

#### 1.2 Finding a service