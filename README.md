* [1. Getting Started with Consul ](https://github.com/japneet-sahni/consul#1-getting-started-with-consul)
* [2. Service Discovery](https://github.com/japneet-sahni/consul#2-service-discovery)
* [3. Dynamic Configuration](https://github.com/japneet-sahni/consul#3-dynamic-configuration)
* [4. Security](https://github.com/japneet-sahni/consul#4-security)
* [5. Infrastructure & High Availability](https://github.com/japneet-sahni/consul#5-infrastructure--high-availability)
* [6. Consul Enterprise](https://github.com/japneet-sahni/consul#6-consul-enterprise)

# 1. Getting Started with Consul
## 1.1. Starting Consul in Dev Mode
```sh
# consul agent -dev --client 0.0.0.0 -bind=10.128.0.5 (bind ip is eth0 interface in ifconfig) - {{ GetInterfaceIP "eth0" }}
# consul agent -join 10.128.0.5 -bind 10.128.0.7 --data-dir /opt/consul

# consul members
Node              Address          Status  Type    Build   Protocol  DC   Segment
consul-server-01  10.128.0.5:8301  alive   server  1.10.1  2         dc1  <all>
consul-client-01  10.128.0.7:8301  alive   client  1.10.1  2         dc1  <default>
```

## 1.2. Remote Execution 
#### (disabled by default post v0.8, needs to be enabled first for each server/client)
#### consul agent -dev --client 0.0.0.0 -bind=10.128.0.5 -hcl='disable_remote_exec=false'
#### consul exec ping google.com
```sh
consul-server-01: PING google.com (209.85.200.139) 56(84) bytes of data.
consul-server-01: 64 bytes from jl-in-f139.1e100.net (209.85.200.139): icmp_seq=1 ttl=115 time=1.10 ms
consul-server-01:
consul-server-01: 64 bytes from jl-in-f139.1e100.net (209.85.200.139): icmp_seq=2 ttl=115 time=1.13 ms
```

## 1.3. Configuration Directory
#### consul agent --config-dir=/opt/config
```sh
data_dir =  "/opt/consul"
start_join = ["10.128.0.5"]
bind_addr = "10.128.0.7"
```

## 1.4. Agent Leave Behavior
#### Graceful Exit : Agent notifies the cluster and is then removed (ctrl +c or killall -s 2 consul)
```sh
^C2021-08-23T00:22:14.391Z [INFO]  agent: Caught: signal=interrupt
2021-08-23T00:22:14.391Z [INFO]  agent: Gracefully shutting down agent...
2021-08-23T00:22:14.391Z [INFO]  agent.client: client starting leave
2021-08-23T00:22:14.763Z [INFO]  agent.client.serf.lan: serf: EventMemberLeave: consul-client-01 10.128.0.7
```

#### Forced Removal : Agent is not removed and DC will detect failure and replication will continously retry (killall -s 9 consul)

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

## 1.5. Starting Consul in Server Mode
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

## 1.6. Systemd file

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

# 2. Service Discovery
## 2.1. Implementation

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

### 2.1.1 Registering a service
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
# or
consul services register web.json
```

### 2.1.2 Finding a service
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

### 2.1.2 Monitoring a service
#### After this step the service health check should also come into picture based on the health check output (below is a script check using curl)
- Script Check : The output of a script check is limited to 4KB. (0-passing, 1-warning, other-failing)
- HTTP : The status of the service depends on the HTTP response code: any 2xx code is considered passing, a 429 Too ManyRequests is a warning, and anything else is a failure. 
- TCP : If the connection is accepted, the status is success, otherwise the status is critical
```sh
{
  "service": {
    "name": "web",
    "port": 80,
    "check": {
        "args": [ "curl", "127.0.0.1"],
#       "http": "https://localhost:5000/health",
#       "tcp": "localhost:22",
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

# 3. Dynamic Configuration
## 3.1. Key-Value Store
### Object size can't be > 512KB
```sh
consul kv put max_memory 512M
consul kv get max_memory
consul kv delete max_memory
```

## 3.2. Watches
### Checks for changes made to diff consul types like key, keyprefixes, services, nodes, checks, events. If change is deteched an external handler is invoked.

```sh
consul watch -type=key -key=max_memory ./script.sh

### Stop nginx and you will notice one failed check
consul watch -type=checks -state critical
```

## 3.3. Consul templates
### Not a feature of consul but a different binary altogether. Reads the template file and stores the value in output.txt
```sh
### key.tpl
{{ key "max_memory" }}

### Runs continously
consul-template -template "key.tpl:output.txt"
### Runs once
consul-template -template "key.tpl:output.txt" -once

### Configuration File:
vi /tmp/consul-template-config.hcl

consul {
 address = "127.0.0.1:8500"
}
template {
 source = "/root/template/course.tpl"
 destination = "/root/template/course-newname.txt"
 command = "echo Modified > /root/template/delta.txt"
}

consul-template -config "/tmp/consul-template-config.hcl"
```

## 3.4. envconsul
### Launch a subprocess with envt. variables populated from consul & vault. envconsul will connect to consul/vault, read data from KV with prefix specified and populates the envt. variables with the same key names.

```sh
envconsul -prefix my-app env
```

# 4. Security
## 4.1. Consul Connect
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
cd /etc/consul.d/
```
```sh
vi backend-service.hcl
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
vi frontend-service.hcl
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
    id       = "frontend-service-check"
    http     = "http://localhost:8080"
    method   = "GET"
    interval = "1s"
    timeout  = "1s"
  }
}
```

```sh
### Add following line in consul.hcl
connect {
  enabled = true
}

systemctl restart consul
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
# netstat -ntlp
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
# curl localhost:8080
Backend Service
```

## 4.2 Intentions & precedence
### Intentions
```sh
# consul intention create -deny frontend-service backend-service
Created: frontend-service => backend-service (deny)
# consul intention list
ID                                    Source            Action  Destination      Precedence
fe489aee-b2a6-7ba1-030f-0ec909f9a591  frontend-service  deny    backend-service  9
# consul intention get fe489aee-b2a6-7ba1-030f-0ec909f9a591
Source:       frontend-service
Destination:  backend-service
Action:       deny
ID:           fe489aee-b2a6-7ba1-030f-0ec909f9a591
Created At:   Wednesday, 25-Aug-21 13:51:53 UTC
# consul intention match backend-service
frontend-service => backend-service (deny)
# consul intention match -source frontend-service
frontend-service => backend-service (deny)
# consul intention delete frontend-service backend-service
Intention deleted.
```
### Precedence
```sh
Exact Exact - 9
  *   Exact - 8
Exact   *   - 6
  *     *   - 2
```

## 4.3 Consul ACL's
### Secures access to UI, API,CLI, service and agent communications

```sh
### Add to consul.hcl to enable ACL
acl = {
  enabled = true
  default_policy = "deny"
  enable_token_persistence = true
}

# consul acl bootstrap
AccessorID:       7226cc73-5b23-eff0-b8f5-76b143eca893
SecretID:         88f95e1a-70fe-4876-de5e-a88d0d5a17d7
Description:      Bootstrap Token (Global Management)
Local:            false
Create Time:      2021-08-25 19:02:31.46557543 +0000 UTC
Policies:
   00000000-0000-0000-0000-000000000001 - global-management

# consul members -token=88f95e1a-70fe-4876-de5e-a88d0d5a17d7
# export CONSUL_HTTP_TOKEN=88f95e1a-70fe-4876-de5e-a88d0d5a17d7
# export CONSUL_HTTP_TOKEN_FILE=/tmp/token-file

vi /tmp/token-file
88f95e1a-70fe-4876-de5e-a88d0d5a17d7
```
### Wildcard based access Policy
```sh
key_prefix "" {
  policy = "read"
}

# consul acl policy create -name "new-policy" -rules @rules.hcl
# consul acl policy create -name "new-policy" -token-secret 8a2abe46-8e00-14ca-1795-89d3f8966837 (secret ID)
```

## 4.4 Anonymous Tokens
- Cannot be deleted
- Access things without logging in.
- Required for DNS service discovery (dig on 8600 won't return any A record)

```sh
AccessorID:       00000000-0000-0000-0000-000000000002
SecretID:         anonymous
Description:      Anonymous Token
```
```sh
service_prefix "" {
  policy = "read"
}
key_prefix "" {
  policy = "read"
}
node_prefix "" {
  policy = "read"
}
```

## 4.5 ACL's on Agents

```sh
agent.http: Request error: method=POST url=/v1/agent/connect/authorize from=127.0.0.1:36160 error="Permission denied"

agent: Coordinate update blocked by ACLs: accessorID=00000000-0000-0000-0000-000000000002

agent.proxycfg: Failed to handle update from watch: service_id=backend-service-sidecar-proxy id=leaf error="error filling agent cache: Permission denied"
```
### These node agent errors require to setup an agent token with following policies
### 4.5.1 Create following policy
```sh
node_prefix "" {
  policy = "write"
}
service_prefix "" {
   policy = "read"
}
```

### 4.5.2 Add token within configuration file:
### vi consul.hcl on server
```sh
acl = {
  enabled = true
  default_policy = "deny"
  enable_token_persistence = true
  tokens {
    "agent" = "f1f30bb8-af83-ac3e-8944-efe03d782ac6"
    "default" = "f1f30bb8-af83-ac3e-8944-efe03d782ac6"
  }
}
```

### vi consul.hcl on client
```sh
acl = {
  tokens {
    "agent" = "f1f30bb8-af83-ac3e-8944-efe03d782ac6"
    "default" = "f1f30bb8-af83-ac3e-8944-efe03d782ac6"
  }
}
```

## 4.6 Gossip Encryption
- Consul uses a gossip protocol to manage membership and broadcast messages to the cluster.
- Each datacenter that Consul operates in has a *LAN gossip pool* containing all members of the datacenter (clients and servers). (TCP/UDP/8301)
- Membership information provided by the *WAN pool* allows servers to perform cross-datacenter requests. (TCP/UDP/8302)
- *Server RPC* is used by servers to handle incoming requests from other agents. (TCP/8300)
- All the data goes is exchanged in plaintext if not encrypted.
- Check using *tcpdump -i any port 8301 -vv -X*
### 4.6.1 Generate Cryptographic Key:
```sh
consul keygen
```
### 4.6.2 Add below config to server consul.hcl
```sh
cd /etc/consul.d
vi consul.hcl
encrypt = "SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I="
```
### If the encryption is not enabled on client, the client will start failing with below eeror
```sh
### client
agent.client.memberlist.lan: memberlist: Failed fallback ping: Remote state is encrypted and encryption is not configured
### server
agent.server.memberlist.lan: memberlist: failed to receive: Encryption is configured but remote state is not encrypted from=10.128.0.7:44246
```
### 4.6.3 Add below config to client consul.hcl
```sh
cd /etc/consul.d
vi consul.hcl
encrypt = "SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I="
```

## 4.7 Gossip Encryption in existing DC
### 4.7.1 Set both flags to false
```sh
### Agents will be able to decrypt the incoming traffic but will not be able to send encrypted traffic
encrypt = "SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I=",
encrypt_verify_incoming = false,
encrypt_verify_outgoing = false
```
```sh
systemctl restart consul
```
### 4.7.2 Set outgoing to true
```sh
### Agents will be able to decrypt the incoming traffic but will now be able to send encrypted traffic
encrypt = "SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I=",
encrypt_verify_incoming = false,
encrypt_verify_outgoing = true
```
```sh
systemctl restart consul
```
### 4.7.3 Set incoming to true
```sh
### Both incoming and outgoing traffic will enforce encryption
encrypt = "SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I=",
encrypt_verify_incoming = true,
encrypt_verify_outgoing = true
```
```sh
systemctl restart consul
```

## 4.8 Rotation of Gossip ENcryption Keys

```sh
# consul keyring -list
==> Gathering installed encryption keys...
WAN:
  SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I= [1/1]
dc1 (LAN):
  SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I= [2/2]

# consul keygen
yWQ6bFoYaOXoOSIAi4L+reX3QheYPHW1GAMezG2gNvk=

# consul keyring -install yWQ6bFoYaOXoOSIAi4L+reX3QheYPHW1GAMezG2gNvk=
==> Installing new gossip encryption key...

# consul keyring -list
==> Gathering installed encryption keys...
WAN:
  SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I= [1/1]
  yWQ6bFoYaOXoOSIAi4L+reX3QheYPHW1GAMezG2gNvk= [1/1]
dc1 (LAN):
  yWQ6bFoYaOXoOSIAi4L+reX3QheYPHW1GAMezG2gNvk= [2/2]
  SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I= [2/2]

# consul keyring -use yWQ6bFoYaOXoOSIAi4L+reX3QheYPHW1GAMezG2gNvk=
==> Changing primary gossip encryption key...
# consul keyring -list
==> Gathering installed encryption keys...
WAN:
  SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I= [1/1]
  yWQ6bFoYaOXoOSIAi4L+reX3QheYPHW1GAMezG2gNvk= [1/1]
dc1 (LAN):
  yWQ6bFoYaOXoOSIAi4L+reX3QheYPHW1GAMezG2gNvk= [2/2]
  SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I= [2/2]

# cat /opt/consul/serf/local.keyring
[
  "yWQ6bFoYaOXoOSIAi4L+reX3QheYPHW1GAMezG2gNvk=",
  "SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I="
]

# consul keyring -remove SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I=
==> Removing gossip encryption key...

# cat /opt/consul/serf/local.keyring
[
  "yWQ6bFoYaOXoOSIAi4L+reX3QheYPHW1GAMezG2gNvk="
]

# consul keyring -list=
==> Gathering installed encryption keys...
WAN:
  yWQ6bFoYaOXoOSIAi4L+reX3QheYPHW1GAMezG2gNvk= [1/1]
dc1 (LAN):
  yWQ6bFoYaOXoOSIAi4L+reX3QheYPHW1GAMezG2gNvk= [2/2]
[root@consul-server-01 consul.d]# 
```

## 4.9 RPC Encryption

## 4.9.1 Steps to see RPC data in plaintext
```sh
# consul kv get max_memory (on Client)
# tcpdump -i any port 8300 -vv -X (Onserver)
### max_memory kv is in plaintext
    consul-server-01.us-central1 > consul-client-01.us-central1: Flags [P.], cksum 0x15ff (incorrect -> 0x0959), seq 71:276, ack 553, win 481, options [nop,nop,TS val 842778517 ecr 2221329016], length 205
        "0x0000:  4500 0101 e0a0 4000 4006 444b 0a80 0005  E.....@.@.DK....
        0x0010:  0a80 0007 206c e70b b64d c1e6 e6f1 ce22  .....l...M.....
        0x0020:  8018 01e1 15ff 0000 0101 080a 323b c795  ............2;..
        0x0030:  8466 ca78 83a5 4572 726f 72a0 a353 6571  .f.x..Error..Seq
        0x0040:  0bad 5365 7276 6963 654d 6574 686f 64a7  ..ServiceMethod.
        0x0050:  4b56 532e 4765 7487 a742 6163 6b65 6e64  KVS.Get..Backend
        0x0060:  00b0 436f 6e73 6973 7465 6e63 794c 6576  ..ConsistencyLev
        0x0070:  656c a0a7 456e 7472 6965 7391 87ab 4372  el..Entries...Cr
        0x0080:  6561 7465 496e 6465 78cd 014d a546 6c61  eateIndex..M.Fla
        0x0090:  6773 00a3 4b65 79aa 6d61 785f 6d65 6d6f  gs..Key.max_memo
        0x00a0:  7279 a94c 6f63 6b49 6e64 6578 00ab 4d6f  ry.LockIndex..Mo
        0x00b0:  6469 6679 496e 6465 78cd 137c a753 6573  difyIndex..|.Ses
        0x00c0:  7369 6f6e a0a5 5661 6c75 65a5 3130 3234  sion..Value.1024
        0x00d0:  4da5 496e 6465 78cd 137c ab4b 6e6f 776e  M.Index..|.Known
        0x00e0:  4c65 6164 6572 c3ab 4c61 7374 436f 6e74  Leader..LastCont
        0x00f0:  6163 7400 ab4e 6f74 4d6f 6469 6669 6564  act..NotModified
        0x0100:  c2"
```

## 4.9.2 Steps to enable RPC encryption
```sh
# consul tls ca create
==> Saved consul-agent-ca.pem
==> Saved consul-agent-ca-key.pem

# consul tls cert create -server
==> WARNING: Server Certificates grants authority to become a
    server and access all state in the cluster including root keys
    and all ACL tokens. Do not distribute them to production hosts
    that are not server nodes. Store them as securely as CA keys.
==> Using consul-agent-ca.pem and consul-agent-ca-key.pem
==> Saved dc1-server-consul-0.pem
==> Saved dc1-server-consul-0-key.pem

# Copy the CA Certificate to client
base64 -i consul-agent-ca.pem (server)
cd /tmp (client)
vi tmp.txt (Paste the base64 encoded and save)
cat tmp.txt | base64 -d > /etc/consul.d/consul-agent-ca.pem

# Configure Server Configuration:
vi /etc/consul.d/consul.hcl

verify_incoming = true,
verify_outgoing = true,
verify_server_hostname = true,
ca_file = "/etc/consul.d/consul-agent-ca.pem",
cert_file = "/etc/consul.d/dc1-server-consul-0.pem",
key_file = "/etc/consul.d/dc1-server-consul-0-key.pem",
auto_encrypt {
  allow_tls = true
}

# Configure Client Configuration:
vi /etc/consul.d/consul.hcl

verify_incoming = false,
verify_outgoing = true,
verify_server_hostname = true,
ca_file = "/etc/consul.d/consul-agent-ca.pem",
auto_encrypt = {
  tls = true
}

# Verfication:
tcpdump -i any port 8300 -vv -X
consul kv get max_memory
```

## 4.9.3 Methods of distributing client certificates
- Auto-Encrypt : Server distributes the certificates to clients
- Operator : Recommended if you are using third part CA.

## 4.9.4 Verify Server Hostname

### In order to authenticate to consul servers, servers are provided with a certificate which contains server.dc1.consul in common name and subject alternative name.

```sh
# openssl x509 -in dc1-server-consul-0.pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            70:24:c0:86:76:2c:3f:dd:0c:f9:13:d4:8b:30:9f:b7
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C = US, ST = CA, L = San Francisco, street = 101 Second Street, postalCode = 94105, O = HashiCorp Inc., CN = Consul Agent CA 186092156626166931642602780217796350062
        Validity
            Not Before: Aug 26 12:51:58 2021 GMT
            Not After : Aug 26 12:51:58 2022 GMT
#       Subject: CN = server.dc1.consul
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:1d:e8:ad:77:9d:ef:a7:0c:78:33:9b:f3:09:ac:
                    db:2d:97:4c:56:9a:9f:e7:79:07:91:9f:04:1f:99:
                    d3:ca:13:19:5b:82:df:6b:93:1a:39:62:cb:11:02:
                    e4:41:de:eb:d6:af:10:ac:3f:67:0d:47:74:3d:a7:
                    d9:72:b3:d4:7d
                ASN1 OID: prime256v1
                NIST CURVE: P-256
#            X509v3 Subject Alternative Name: 
#                DNS:server.dc1.consul, DNS:localhost, IP Address:127.0.0.1
```
### Therefore, if you enable verify_server_hostname = true, only agents that provide such certificate are allowed to boot as server. This setting is critical to prevent a compromised client from being restarted as a server.

## 4.10 API
### For HTTP API requests with ACL, you need to send *X-Consul-Token* header

```sh
curl localhost:8500/v1/catalog/nodes?pretty
curl localhost:8500/v1/kv/max_memory?pretty
curl --request DELETE localhost:8500/v1/kv/max_memory
curl --header "X-Consul-Token: 88f95e1a-70fe-4876-de5e-a88d0d5a17d7" localhost:8500/v1/kv/max_memory
# raw gives decoded value
curl localhost:8500/v1/kv/max_memory?raw
# to get all keys without values
curl localhost:8500/v1/kv/?keys
```
## 4.11 Final consul.hcl files
```sh
# Server
data_dir =  "/opt/consul"
bind_addr = "10.128.0.5"
client_addr = "0.0.0.0"
bootstrap_expect = 1
node_name = "consul-server"
ui = true
server = true
enable_local_script_checks = true
connect {
  enabled = true
}
acl = {
  enabled = true
  default_policy = "deny"
  enable_token_persistence = true
  tokens {
    "agent" = "8a2abe46-8e00-14ca-1795-89d3f8966837"
    "default" = "8a2abe46-8e00-14ca-1795-89d3f8966837"
  }
}
encrypt = "SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I="
encrypt_verify_incoming = true
encrypt_verify_outgoing = true
verify_incoming = true
verify_outgoing = true
verify_server_hostname = true
ca_file = "/etc/consul.d/consul-agent-ca.pem"
cert_file = "/etc/consul.d/dc1-server-consul-0.pem"
key_file = "/etc/consul.d/dc1-server-consul-0-key.pem"
auto_encrypt {
  allow_tls = true
}
```
```sh
# Client
data_dir =  "/opt/consul"
start_join = ["10.128.0.5"]
bind_addr = "10.128.0.7"
enable_local_script_checks = true
encrypt = "SPBrsLMKqry5F0mDp+YScCDjWmVu6gVbKjGm3BN9d3I="
encrypt_verify_incoming = true
encrypt_verify_outgoing = true
acl = {
  tokens {
    "agent" = "8a2abe46-8e00-14ca-1795-89d3f8966837"
    "default" = "8a2abe46-8e00-14ca-1795-89d3f8966837"
  }
}
verify_incoming = false,
verify_outgoing = true,
verify_server_hostname = true,
ca_file = "/etc/consul.d/consul-agent-ca.pem",
auto_encrypt = {
  tls = true
}
```

# 5. Infrastructure & High Availability
## 5.1. High Availability
### -bootstrap-expect=3 : Informs Consul of the expected number of server nodes and automatically bootstraps when that many servers are available.

```sh
# Consul Server 1: The agent will start running but the leader won't be selected.
consul agent -server -bootstrap-expect=3 -bind=10.128.0.5 -client 0.0.0.0 -data-dir=/opt/consul -ui=true

# Consul Server 2: 
consul agent -server -bind=10.128.0.6 -client 0.0.0.0 -data-dir=/opt/consul -ui=true
consul join 10.128.0.5

# Consul Server 3:
consul agent -server -bind=10.128.0.8 -client 0.0.0.0 -data-dir=/opt/consul -ui=true
consul join 10.128.0.5

# Which is the leader
consul operator raft list-peers
```

## 5.2 Multiple DC
- Datacenter is a networking environment that is private, low latency and high bandwidth. A single AZ in AWS region will correspond to one DC.
- The DC's can be on different cloud service providers or even on-premise. 
- The DC's are connected through WAN which is high latency.
- All server nodes must be able to talk to each other otherwise gossip protocol or RPC forwarding will not work.
- Data is not replicated between different DC's. When a request is made for a DC from the other one, the local DC will make a RPC request to other DC to fetch resources.
### 5.2.1 Implementation
```sh
# Add datacenter value in consul.hcl for both servers
datacenter: India
datacenter: Japan

# consul members -wan
# cosnul join -wan <server 1 IP>
# consul catalog datacenters
```

## 5.3 Prepared Query
### Use Case 1 : If there are multiple versions of an application, you can explicitly specify a version in prepared query that needs to be returned to the client.
```sh
# Add tags and ids to 2 web service definitions running on different ports
"name": "web"
"id": "web1"
"tags": "[v1]"

"name": "web"
"id": "web1"
"tags": "[v2]"

# Create prepared query json
vi /etc/consul.d/prepared-query.json
{
  "Name": "web-service",
  "Service": {
    "Service": "web",
    "Tags": ["v2"]
  }
}

# Publish the prepared query created above
curl --request POST --data @prepared-query.json http://127.0.0.1:8500/v1/query

# This will return IP and port for v2 of web service
dig @localhost -p 8600 web-service.query.consul SRV

# List prepared query: This will also give uuid of the query
curl http://127.0.0.1:8500/v1/query

# Update prepared query
curl --request PUT --data @prepared-query.json http://127.0.0.1:8500/v1/query/<uuid>

# Delete prepared query
curl --request DELETE http://127.0.0.1:8500/v1/query/<uuid>
```

### Use Case 2 : Failover Policy - You can contact other DC's if there are no healthy instances in local DC.

```sh
vi /etc/consul.d/failover.json
{
  "Name": "failover",
  "Service": {
    "Service": "database",
    "Tags": ["v1"],
    "Failover": {
      "Datacenters": ["singapore"]
      "NearestN": 3
    }
  }
}

# NearestN in prepared query specifies that the query will be forwarded to up to NearestN other datacenters based on their estimated network round trip time using Network Coordinates from the WAN gossip pool
```

## 5.4. Backup & restore
- Snapshots will not be saved if DC is degraded or if no leader is available
- It is possible to run snapshot on any follower server using stale consistency mode.
```sh
consul snapshot save backup.snap
consul snapshot restore backup.snap
```

## 5.5 Auto-pilot
- Autopilot features allow for automatic, operator-friendly management of Consul servers. 
- It includes cleanup of dead servers, monitoring the state of the Raft cluster, and stable server introduction.
- When a new server is added to the datacenter, there is a waiting period where it must be healthy and stable for a certain amount of time before being promoted to a full, voting member. This is defined by the ServerStabilizationTime autopilot's parameter and by default is 10 seconds.
- With Autopilot's dead server cleanup enabled, dead servers will periodically be cleaned up and removed from the Raft peer set to prevent them from interfering with the quorum size and leader elections. The cleanup process will also be automatically triggered whenever a new server is successfully added to the datacenter.
- Enterprise features
  - Redundancy Zones
  - Automated upgrades

```sh
# See Details of Servers & Verify Autopilot settings (consul-01):
consul operator raft list-peers
consul operator autopilot get-config

# CleanupDeadServers = true
# LastContactThreshold = 200ms
# MaxTrailingLogs = 250
# MinQuorum = 0
# ServerStabilizationTime = 10s
# RedundancyZoneTag = ""
# DisableUpgradeMigration = false
# UpgradeVersionTag = ""

# Modify Autopilot Settings (leader node):
consul operator autopilot set-config -server-stabilization-time=60s
consul operator autopilot set-config -cleanup-dead-servers=false
```
## 5.6 Autojoining

```sh
# Retry Join
consul agent -retry-join 10.128.0.5 -bind 10.128.0.7 --data-dir /opt/consul -retry-interval 5s
```

```sh
# Auto Join using provider tags
consul agent -retry-join "provider=aws tag_key=Name tag_value=consul-server" -data-dir /root/consul -retry-interval 5s
```

## 5.7 Consul logs

```sh
consul monitor --log-level=trace

# Debug captures all agent,cluster,host information. Interval is 30s and duration is 2m.
consul debug
```

# 6. Consul Enterprise
## 6.1 Installation
```sh
consul license get
vi consul.lic (copy the trial 30 day license key)
consul license put @consul.lic
consul license put - (using stdin)
```

## 6.2 Namespaces

```sh
vi bob-team.hcl
name = "bob-team"

consul namespace write bob-team.hcl

# <service-name>.service.<ns_name>.<dc_name>.consul
dig @localhost -p 8600 web-service.service.bob-team.dc1.consul SRV
```

## 6.3 Automated backups
- Enterprise-only feature that automatically manages on taking snapshots, backup rotation and sending backup files to s3.
- Registers itself as a service.
```sh
consul snapshot agent
```

## 6.4 Redundancy Zones 
- Autopilot allows you to add “non-voting” servers to your datacenter that will be promoted to the "voting" status in case of voting server failure in an availability zone.

```sh
# Add 3 different zones to 3 voting consul servers
node_meta {
  zone = "zone1/zone2/zone3"
}

# Update Autopilot configuration to reflect node_meta:
consul operator autopilot set-config -redundancy-zone-tag=zone

# Add below to 3 non-voting consul servers
node_meta {
  zone = "zone1/zone2/zone3"
}
autopilot {
  redundancy_zone_tag = "zone"
}
```

## 6.5 Automated upgrades
- Autopilot allows you to add new servers directly to the datacenter and waits until you have enough servers running the new version to perform a leadership change and demote the old servers as "non-voters".
