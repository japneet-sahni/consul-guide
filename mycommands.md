# consul agent -dev --client 0.0.0.0 -bind=10.128.0.5 (bind ip is eth0 interface in ifconfig)
# consul agent -join 10.128.0.5 -bind 10.128.0.7 --data-dir /path/dir

# consul members
Node              Address          Status  Type    Build   Protocol  DC   Segment
consul-server-01  10.128.0.5:8301  alive   server  1.10.1  2         dc1  <all>
consul-client-01  10.128.0.7:8301  alive   client  1.10.1  2         dc1  <default>

Remote Execution (disabled by default post v0.8, needs to be enabled first for each server/client)
# consul agent -dev --client 0.0.0.0 -bind=10.128.0.5 -hcl='disable_remote_exec=false'
# consul exec ping google.com