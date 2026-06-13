# [glider](https://github.com/nadoo/glider)

[![Go Version](https://img.shields.io/github/go-mod/go-version/nadoo/glider?style=flat-square)](https://go.dev/dl/)
[![Go Report Card](https://goreportcard.com/badge/github.com/nadoo/glider?style=flat-square)](https://goreportcard.com/report/github.com/nadoo/glider)
[![GitHub release](https://img.shields.io/github/v/release/nadoo/glider.svg?style=flat-square&include_prereleases)](https://github.com/nadoo/glider/releases)
[![Actions Status](https://img.shields.io/github/actions/workflow/status/nadoo/glider/build.yml?branch=dev&style=flat-square)](https://github.com/nadoo/glider/actions)
[![DockerHub](https://img.shields.io/docker/image-size/nadoo/glider?color=blue&label=docker&style=flat-square)](https://hub.docker.com/r/nadoo/glider)

glider is a forward proxy with multiple protocols support, and also a dns/dhcp server with ipset management features(like dnsmasq).

we can set up local listeners as proxy servers, and forward requests to internet via forwarders.

```bash
                |Forwarder ----------------->|
   Listener --> |                            | Internet
                |Forwarder --> Forwarder->...|
```

## Features
- Act as both proxy client and proxy server(protocol converter)
- Flexible proxy & protocol chains
- Load balancing with the following scheduling algorithm:
  - rr: round robin
  - ha: high availability 
  - lha: latency based high availability
  - dh: destination hashing
- Rule & priority based forwarder choosing: [Config Examples](config/examples)
- DNS forwarding server:
  - dns over proxy
  - force upstream querying by tcp
  - association rules between dns and forwarder choosing
  - association rules between dns and ipset
  - dns cache support
  - custom dns record
- IPSet management (linux kernel version >= 2.6.32):
  - add ip/cidrs from rule files on startup
  - add resolved ips for domains from rule files by dns forwarding server
- Serve http and socks5 on the same port
- Periodical availability checking for forwarders
- Send requests from specific local ip/interface
- Services: 
  - dhcpd: a simple dhcp server that can run in failover mode

## Protocols

<details>
<summary>click to see details</summary>

|Protocol       | Listen/TCP |  Listen/UDP | Forward/TCP | Forward/UDP | Description
|:-:            |:-:|:-:|:-:|:-:|:-
|Mixed          |√|√| | |http+socks5 server
|HTTP           |√| |√| |client & server
|SOCKS5         |√|√|√|√|client & server
|SS             |√|√|√|√|client & server
|Trojan         |√|√|√|√|client & server
|Trojanc        |√|√|√|√|trojan cleartext(without tls)
|VLESS          |√|√|√|√|client & server
|VMess          | | |√|√|client only
|SSR            | | |√| |client only
|SSH            | | |√| |client only
|SOCKS4         | | |√| |client only
|SOCKS4A        | | |√| |client only
|TCP            |√| |√| |tcp tunnel client & server
|UDP            | |√| |√|udp tunnel client & server
|TLS            |√| |√| |transport client & server
|KCP            | |√|√| |transport client & server
|Unix           |√|√|√|√|transport client & server
|VSOCK          |√| |√| |transport client & server
|Smux           |√| |√| |transport client & server
|Websocket(WS)  |√| |√| |transport client & server
|WS Secure      |√| |√| |websocket secure (wss)
|Proxy Protocol |√| | | |version 1 server only
|Simple-Obfs    | | |√| |transport client only
|Redir          |√| | | |linux redirect proxy
|Redir6         |√| | | |linux redirect proxy(ipv6)
|TProxy         | |√| | |linux tproxy(udp only)
|Reject         | | |√|√|reject all requests

</details>

## Install

- Binary: [https://github.com/nadoo/glider/releases](https://github.com/nadoo/glider/releases)
- Docker: `docker pull nadoo/glider`
- Manjaro: `pamac install glider`
- ArchLinux: `sudo pacman -S glider`
- Homebrew: `brew install glider`
- MacPorts: `sudo port install glider`
- Source: `go install github.com/nadoo/glider@latest`

## Usage

#### Run

```bash
glider -verbose -listen :8443
# docker run --rm -it nadoo/glider -verbose -listen :8443
```

#### Help

<details>
<summary><code>glider -help</code></summary>

```bash
Usage: glider [-listen URL]... [-forward URL]... [OPTION]...

  e.g. glider -config /etc/glider/glider.conf
       glider -listen :8443 -forward socks5://serverA:1080 -forward socks5://serverB:1080 -verbose

OPTION:
  -check string
        check=tcp[://HOST:PORT]: tcp port connect check
        check=http://HOST[:PORT][/URI][#expect=REGEX_MATCH_IN_RESP_LINE]
        check=https://HOST[:PORT][/URI][#expect=REGEX_MATCH_IN_RESP_LINE]
        check=file://SCRIPT_PATH: run a check script, healthy when exitcode=0, env vars: FORWARDER_ADDR,FORWARDER_URL
        check=disable: disable health check (default "http://www.msftconnecttest.com/connecttest.txt#expect=200")
  -checkdisabledonly
        check disabled fowarders only
  -checkinterval int
        fowarder check interval(seconds) (default 30)
  -checklatencysamples int
        use the average latency of the latest N checks (default 10)
  -checktimeout int
        fowarder check timeout(seconds) (default 10)
  -checktolerance int
        fowarder check tolerance(ms), switch only when new_latency < old_latency - tolerance, only used in lha mode
  -config string
        config file path
  -dialtimeout int
        dial timeout(seconds) (default 3)
  -dns string
        local dns server listen address
  -dnsalwaystcp
        always use tcp to query upstream dns servers no matter there is a forwarder or not
  -dnscachelog
        show query log of dns cache
  -dnscachesize int
        max number of dns response in CACHE (default 4096)
  -dnsmaxttl int
        maximum TTL value for entries in the CACHE(seconds) (default 1800)
  -dnsminttl int
        minimum TTL value for entries in the CACHE(seconds)
  -dnsnoaaaa
        disable AAAA query
  -dnsrecord value
        custom dns record, format: domain/ip
  -dnsserver value
        remote dns server address
  -dnstimeout int
        timeout value used in multiple dnsservers switch(seconds) (default 3)
  -example
        show usage examples
  -forward value
        forward url, see the URL section below
  -include value
        include file
  -interface string
        source ip or source interface
  -listen value
        listen url, see the URL section below
  -logflags int
        do not change it if you do not know what it is, ref: https://pkg.go.dev/log#pkg-constants (default 19)
  -maxfailures int
        max failures to change forwarder status to disabled (default 3)
  -mode string
        run mode: admin or node
  -node-id string
        unique node id for node mode
  -central-url string
        central control plane base URL
  -node-token string
        node sync bearer token
  -sync-interval string
        node config sync interval (default "30s")
  -cache-dir string
        node local config cache directory (default "/var/lib/glider/cache")
  -cert-dir string
        node certificate cache directory (default "/etc/glider-certs")
  -traffic-interface string
        interface used for node traffic counters (default "eth0")
  -public-ip string
        public IP reported in node heartbeat
  -relaytimeout int
        relay timeout(seconds)
  -rulefile value
        rule file path
  -rules-dir string
        rule file folder
  -scheme string
        show help message of proxy scheme, use 'all' to see all schemes
  -service value
        run specified services, format: SERVICE_NAME[,SERVICE_CONFIG]
  -strategy string
        rr: Round Robin mode
        ha: High Availability mode
        lha: Latency based High Availability mode
        dh: Destination Hashing mode (default "rr")
  -tcpbufsize int
        tcp buffer size in Bytes (default 32768)
  -udpbufsize int
        udp buffer size in Bytes (default 2048)
  -verbose
        verbose mode

URL:
   proxy: SCHEME://[USER:PASS@][HOST]:PORT
   chain: proxy,proxy[,proxy]...

    e.g. -listen socks5://:1080
         -listen tls://:443?cert=crtFilePath&key=keyFilePath,http://    (protocol chain)

    e.g. -forward socks5://server:1080
         -forward tls://server.com:443,http://                          (protocol chain)
         -forward socks5://serverA:1080,socks5://serverB:1080           (proxy chain)

SCHEME:
   listen : http kcp mixed pxyproto redir redir6 smux sni socks5 ss tcp tls tproxy trojan trojanc udp unix vless vsock ws wss
   forward: direct http kcp reject simple-obfs smux socks4 socks4a socks5 ss ssh ssr tcp tls trojan trojanc udp unix vless vmess vsock ws wss

   Note: use 'glider -scheme all' or 'glider -scheme SCHEME' to see help info for the scheme.

--
Forwarder Options: FORWARD_URL#OPTIONS
   priority : the priority of that forwarder, the larger the higher, default: 0
   interface: the local interface or ip address used to connect remote server.

   e.g. -forward socks5://server:1080#priority=100
        -forward socks5://server:1080#interface=eth0
        -forward socks5://server:1080#priority=100&interface=192.168.1.99

Services:
   dhcpd: service=dhcpd,INTERFACE,START_IP,END_IP,LEASE_MINUTES[,MAC=IP,MAC=IP...]
          service=dhcpd-failover,INTERFACE,START_IP,END_IP,LEASE_MINUTES[,MAC=IP,MAC=IP...]
     e.g. service=dhcpd,eth1,192.168.1.100,192.168.1.199,720

--
Help:
   glider -help
   glider -scheme all
   glider -example

see README.md and glider.conf.example for more details.
--
glider 0.16.4, https://github.com/nadoo/glider (glider.proxy@gmail.com)
```

</details>

#### Schemes

<details>
<summary><code>glider -scheme all</code></summary>

```bash
Direct scheme:
  direct://

Only needed when you want to specify the outgoing interface:
  glider -verbose -listen :8443 -forward direct://#interface=eth0

Or load balance multiple interfaces directly:
  glider -verbose -listen :8443 -forward direct://#interface=eth0 -forward direct://#interface=eth1 -strategy rr

Or you can use the high availability mode:
  glider -verbose -listen :8443 -forward direct://#interface=eth0&priority=100 -forward direct://#interface=eth1&priority=200 -strategy ha

--
Http scheme:
  http://[user:pass@]host:port

--
KCP scheme:
  kcp://CRYPT:KEY@host:port[?dataShards=NUM&parityShards=NUM&mode=MODE]
  
Available crypt types for KCP:
  none, sm4, tea, xor, aes, aes-128, aes-192, blowfish, twofish, cast5, 3des, xtea, salsa20
  
Available modes for KCP:
  fast, fast2, fast3, normal, default: fast

--
Simple-Obfs scheme:
  simple-obfs://host:port[?type=TYPE&host=HOST&uri=URI&ua=UA]
  
Available types for simple-obfs:
  http, tls

--
Reject scheme:
  reject://

--
Smux scheme:
  smux://host:port

--
Socks4 scheme:
  socks4://host:port

--
Socks5 scheme:
  socks5://[user:pass@]host:port

--
SS scheme:
  ss://method:pass@host:port
  
  Available methods for ss:
    AEAD Ciphers:
      AEAD_AES_128_GCM AEAD_AES_192_GCM AEAD_AES_256_GCM AEAD_CHACHA20_POLY1305 AEAD_XCHACHA20_POLY1305
    Stream Ciphers:
      AES-128-CFB AES-128-CTR AES-192-CFB AES-192-CTR AES-256-CFB AES-256-CTR CHACHA20-IETF XCHACHA20 CHACHA20 RC4-MD5
    Alias:
          chacha20-ietf-poly1305 = AEAD_CHACHA20_POLY1305, xchacha20-ietf-poly1305 = AEAD_XCHACHA20_POLY1305
    Plain: NONE

--
SSH scheme:
  ssh://user[:pass]@host:port[?key=keypath&timeout=SECONDS]
    timeout: timeout of ssh handshake and channel operation, default: 5

--
SSR scheme:
  ssr://method:pass@host:port?protocol=xxx&protocol_param=yyy&obfs=zzz&obfs_param=xyz

--
TLS client scheme:
  tls://host:port[?serverName=SERVERNAME][&skipVerify=true][&cert=PATH][&alpn=proto1][&alpn=proto2]
  
Proxy over tls client:
  tls://host:port[?skipVerify=true][&serverName=SERVERNAME],scheme://
  tls://host:port[?skipVerify=true],http://[user:pass@]
  tls://host:port[?skipVerify=true],socks5://[user:pass@]
  tls://host:port[?skipVerify=true],vmess://[security:]uuid@?alterID=num
  
TLS server scheme:
  tls://host:port?cert=PATH&key=PATH[&alpn=proto1][&alpn=proto2]
  tls://host:port?certDir=DIR[&cert=FALLBACK_CERT&key=FALLBACK_KEY][&alpn=proto1][&alpn=proto2]
  
Proxy over tls server:
  tls://host:port?cert=PATH&key=PATH,scheme://
  tls://host:port?certDir=DIR,scheme://
  tls://host:port?cert=PATH&key=PATH,http://
  tls://host:port?cert=PATH&key=PATH,socks5://
  tls://host:port?cert=PATH&key=PATH,ss://method:pass@

--
Trojan client scheme:
  trojan://pass@host:port[?serverName=SERVERNAME][&skipVerify=true][&cert=PATH]
  trojanc://pass@host:port     (cleartext, without TLS)
  
Trojan server scheme:
  trojan://pass@host:port?cert=PATH&key=PATH[&fallback=127.0.0.1]
  trojanc://pass@host:port[?fallback=127.0.0.1]     (cleartext, without TLS)

--
Unix domain socket scheme:
  unix://path

--
VLESS scheme:
  vless://uuid@host:port[?fallback=127.0.0.1:80]

--
VMess scheme:
  vmess://[security:]uuid@host:port[?alterID=num]
    if alterID=0 or not set, VMessAEAD will be enabled
  
  Available security for vmess:
    zero, none, aes-128-gcm, chacha20-poly1305

--
Websocket client scheme:
  ws://host:port[/path][?host=HOST][&origin=ORIGIN]
  wss://host:port[/path][?serverName=SERVERNAME][&skipVerify=true][&cert=PATH][&host=HOST][&origin=ORIGIN]
  
Websocket server scheme:
  ws://:port[/path][?host=HOST]
  wss://:port[/path]?cert=PATH&key=PATH[?host=HOST]
  
Websocket with a specified proxy protocol:
  ws://host:port[/path][?host=HOST],scheme://
  ws://host:port[/path][?host=HOST],http://[user:pass@]
  ws://host:port[/path][?host=HOST],socks5://[user:pass@]
  
TLS and Websocket with a specified proxy protocol:
  tls://host:port[?skipVerify=true][&serverName=SERVERNAME],ws://[@/path[?host=HOST]],scheme://
  tls://host:port[?skipVerify=true],ws://[@/path[?host=HOST]],http://[user:pass@]
  tls://host:port[?skipVerify=true],ws://[@/path[?host=HOST]],socks5://[user:pass@]
  tls://host:port[?skipVerify=true],ws://[@/path[?host=HOST]],vmess://[security:]uuid@?alterID=num

--
VM socket scheme(linux only):
  vsock://[CID]:port

  if you want to listen on any address, just set CID to 4294967295.
```

</details>

#### Examples

<details>
<summary><code>glider -example</code></summary>

```bash
Examples:
  glider -config glider.conf
    -run glider with specified config file.
  
  glider -listen :8443 -verbose
    -listen on :8443, serve as http/socks5 proxy on the same port, in verbose mode.

  glider -listen socks5://:1080 -listen http://:8080 -verbose
    -multiple listeners: listen on :1080 as socks5 proxy server, and on :8080 as http proxy server.
  
  glider -listen :8443 -forward direct://#interface=eth0 -forward direct://#interface=eth1
    -multiple forwarders: listen on 8443 and forward requests via interface eth0 and eth1 in round robin mode.
  
  glider -listen tls://:443?cert=crtFilePath&key=keyFilePath,http:// -verbose
    -protocol chain: listen on :443 as a https(http over tls) proxy server.
  
  glider -listen http://:8080 -forward socks5://serverA:1080,socks5://serverB:1080
    -proxy chain: listen on :8080 as a http proxy server, forward all requests via forward chain.
  
  glider -listen :8443 -forward socks5://serverA:1080 -forward socks5://serverB:1080#priority=10 -forward socks5://serverC:1080#priority=10
    -forwarder priority: serverA will only be used when serverB and serverC are not available.
  
  glider -listen tcp://:80 -forward tcp://serverA:80
    -tcp tunnel: listen on :80 and forward all requests to serverA:80.
  
  glider -listen udp://:53 -forward socks5://serverA:1080,udp://8.8.8.8:53
    -udp tunnel: listen on :53 and forward all udp requests to 8.8.8.8:53 via remote socks5 server.
  
  glider -verbose -dns=:53 -dnsserver=8.8.8.8:53 -forward socks5://serverA:1080 -dnsrecord=abc.com/1.2.3.4
    -dns over proxy: listen on :53 as dns server, forward to 8.8.8.8:53 via socks5 server.
```

</details>


## Config

```bash
glider -config CONFIG_PATH
```

- [ConfigFile](config)
  - [glider.conf.example](config/glider.conf.example)
  - [office.rule.example](config/rules.d/office.rule.example)
- [Examples](config/examples)
  - [transparent proxy with dnsmasq](config/examples/8.transparent_proxy_with_dnsmasq)
  - [transparent proxy without dnsmasq](config/examples/9.transparent_proxy_without_dnsmasq)

## Central Control Plane And Data Nodes

Glider can run as a centralized control plane plus many lightweight data-plane nodes.

Modes:

- `admin`: runs the Web Admin/API, connects to MongoDB, manages users/rules/nodes/config versions, and exposes `/api/node/config` plus `/api/node/heartbeat`. If `listen`, `dns`, or `service` is configured, admin also starts a local proxy runtime for panel connectivity checks.
- `node`: runs proxy listeners only, does not start the Admin UI, reads cached config first, then pulls config from the central API and hot-reloads only when `config_version` changes.

Recommended central deployment shape:

```text
/root/data/docker_data/glider-admin/
  compose.yml
  .env
  glider.conf
  rules.d/
```

Recommended node deployment shape:

```text
/root/data/docker_data/glider/
  compose.yml
  .env
  glider.conf
  rules.d/
  cache/
```

Keep source code in GitHub and publish versioned images such as `ghcr.io/ferryboatseranade/glider:<version>`. VPS nodes should use fixed image tags instead of `build: ../glider`.

The GitHub Actions build workflow publishes `ghcr.io/<owner>/glider` on `master`, `main`, `dev`, and tag pushes with branch, tag, semver, and `sha-*` tags. When you create a tag such as `v2026.06.08-control56`, the workflow also publishes the same GHCR tag, so compose files can pin that exact version.

Central `.env`:

```dotenv
GLIDER_MODE=admin
GLIDER_MONGO_URI=mongodb://...
GLIDER_MONGO_DB=glider
GLIDER_ADMIN_TOKEN=...
GLIDER_NODE_TOKEN=...
GLIDER_ADMIN_ADDR=:8444
# Optional. Comma/space separated IPs or CIDRs allowed to access Web Admin/API.
# GLIDER_ADMIN_ALLOWED_CIDRS=203.0.113.10/32,2001:db8::/48
GLIDER_ADMIN_TRUST_PROXY_HEADERS=false
GLIDER_SETTINGS_KEY=change-this-32-byte-settings-key
# Optional fallback if Cloudflare is not configured in the Admin UI:
# GLIDER_CLOUDFLARE_API_TOKEN=...
# GLIDER_CLOUDFLARE_ACCOUNT_ID=...
# GLIDER_ACME_EMAIL=admin@example.com
GLIDER_DOMAIN_RECONCILE_INTERVAL=60s
GLIDER_CERT_RENEW_INTERVAL=12h
GLIDER_RULES_HEALTH_INTERVAL=5m
GLIDER_RULES_HEALTH_TARGET=https://ipinfo.io/json
GLIDER_RULES_HEALTH_TIMEOUT=8s
GLIDER_ACME_DNS_PROPAGATION_TIMEOUT=2m
GLIDER_ACME_DNS_POLL_INTERVAL=5s
```

Central `glider.conf` with panel connectivity checks enabled:

```ini
mode=admin
admin=:8444
listen=127.0.0.1:18080
rules-dir=/etc/rules.d
```

Do not publish the local `18080` listener from Docker. It exists only so the Admin panel can run route checks through a local proxy runtime.

Node `.env`:

```dotenv
GLIDER_MODE=node
GLIDER_NODE_ID=dmit-01
GLIDER_CENTRAL_URL=https://central.example.com
GLIDER_NODE_TOKEN=...
GLIDER_SYNC_INTERVAL=30s
GLIDER_CACHE_DIR=/etc/glider-cache
GLIDER_CERT_DIR=/etc/glider-certs
GLIDER_TRAFFIC_INTERFACE=eth0
# Optional override. If empty, admin infers it from node heartbeat requests.
# GLIDER_PUBLIC_IP=203.0.113.10
```

Node `compose.yml` should publish only proxy ports:

```yaml
services:
  glider-node:
    image: ghcr.io/ferryboatseranade/glider:<version>
    container_name: glider
    user: "0:0"
    ports:
      - "443:443"
      - "8443:8443"
    env_file:
      - .env
    volumes:
      - ./glider.conf:/etc/glider.conf:ro
      - ./rules.d:/etc/rules.d
      - ./cache:/etc/glider-cache
      - ./certs:/etc/glider-certs
    command: -config /etc/glider.conf
    restart: unless-stopped
```

Templates are provided in [deploy](deploy):

- [admin.compose.yml](deploy/admin.compose.yml)
- [node.compose.yml](deploy/node.compose.yml)
- [CONTROL_PLANE_STATUS.md](deploy/CONTROL_PLANE_STATUS.md) records the current migration/runtime checklist.

If a tag is temporarily loaded with `docker save | docker load` before it is pushed to GHCR, set `pull_policy: never` in that host's compose file. Remove it after the tag is available from the registry.

Node sync API:

- `GET /api/node/config?node_id=<id>` with `Authorization: Bearer <GLIDER_NODE_TOKEN>` returns `config_version`, `users`, `rules`, and `updated_at`.
- Config sync supports `ETag` / `If-None-Match` using `config_version`. After a node has a current local version, unchanged central config returns `304 Not Modified` so users, passwords, and rules are not repeatedly transferred.
- `POST /api/node/heartbeat` reports node id, hostname, public IP, glider version, config version, certificate version, uptime, total RX/TX bytes, last config/node error, and separate `cert_error` when certificate sync fails.
- `GET /api/config/status` with the admin token returns the central `config_version`, `updated_at`, user count, and rule count. The Admin overview and Nodes table compare this central version with each node heartbeat to show synced/stale state.
- `GLIDER_NODE_TOKEN` is the shared bootstrap token. Admin can also set a dedicated token for a node from the Nodes view or `PUT /api/nodes/<node_id>/token` with the admin token. Dedicated tokens are stored as SHA-256 hashes, never as plaintext.
- If a node has a dedicated token, the node API accepts only that token for its `node_id`. Nodes without a dedicated token continue to use the shared `GLIDER_NODE_TOKEN`, so existing deployments stay compatible while you rotate nodes one by one.
- Admin stores the last successful heartbeat auth mode as `auth_mode=shared` or `auth_mode=dedicated`. The Nodes view shows both configured token state and last auth mode, which helps confirm a node actually switched tokens.

Admin connectivity checks:

- The Admin panel includes a Connectivity view for default, rule, and user route checks.
- `POST /api/check` with the admin token accepts `type`, `name`, `target`, `network`, `timeout`, and `probe`.
- Use `probe=ipinfo` with `target=https://ipinfo.io/json` to see the real exit IP, ASN/org, city, region, country, and timezone for a default, rule, or user route.
- `type=rule` checks the named rule's forward chain directly. `type=user` checks the route bound to that user first, then falls back to target rules.
- `GET` or `POST /api/rules/health` checks every rule against the probe target and returns per-rule status and exit IP information. `POST` saves the result as the latest health snapshot; `GET /api/rules/health?latest=1` returns the most recent saved snapshot without running a new check.
- The admin worker runs rule health checks every `GLIDER_RULES_HEALTH_INTERVAL` and stores the latest snapshot in MongoDB. Set the interval to `0` to disable it. Defaults use `GLIDER_RULES_HEALTH_TARGET=https://ipinfo.io/json` and `GLIDER_RULES_HEALTH_TIMEOUT=8s`.
- Checks run through the local proxy runtime. In `admin` mode, configure a local-only `listen=127.0.0.1:18080` plus `rules-dir` to enable checks. A pure control plane without a local proxy returns a clear unavailable error.

Nodes view:

- `GET /api/nodes` returns nodes that have posted heartbeat records, sorted by last heartbeat time.
- `DELETE /api/nodes/<node_id>` removes a stale node record from the Admin database. It does not stop the node process; a running node will reappear on its next heartbeat.
- `PUT /api/nodes/<node_id>/token` sets a dedicated token for that node. `DELETE /api/nodes/<node_id>/token` clears it and restores shared-token fallback.
- The panel marks nodes as online, stale, offline, or error from the latest heartbeat, node error field, and heartbeat age.
- Nodes report config version, certificate version, uptime, total RX/TX counters, public IP, hostname, last successful auth mode, last config/node error, and separate certificate sync error.
- If a node does not set `GLIDER_PUBLIC_IP`, Admin infers the public IP from the heartbeat request source. If Admin is behind your own trusted reverse proxy, set `GLIDER_ADMIN_TRUST_PROXY_HEADERS=true` to allow headers such as `CF-Connecting-IP`, `X-Real-IP`, and `X-Forwarded-For`. Leave it false when Admin is directly exposed or behind an untrusted proxy.
- Admin can also run external node proxy health checks. Every `GLIDER_NODE_PROXY_HEALTH_INTERVAL` it picks the first enabled, unexpired user credential, connects through each fresh node heartbeat at the node's published HTTP proxy port, and requests `GLIDER_NODE_PROXY_HEALTH_TARGET` (default `https://ipinfo.io/json`). Results are stored on the node as `proxy_status`, `proxy_checked_at`, `proxy_exit_ip`, `proxy_org`, `proxy_http_status`, `proxy_duration_ms`, and `proxy_error`.
- Defaults are `GLIDER_NODE_PROXY_HEALTH_INTERVAL=60s`, `GLIDER_NODE_PROXY_HEALTH_TARGET=https://ipinfo.io/json`, and `GLIDER_NODE_PROXY_HEALTH_TIMEOUT=8s`. Set the interval to `0` to disable Admin-side node proxy checks.
- A fresh proxy health error blocks automatic DNS failover to or from that node even if heartbeat is still fresh. This catches cases where the node process is alive but its public proxy entry point or user authentication path is broken.

Servers and remote provisioning:

- The Admin panel includes a Servers tab for VPS inventory and SSH-based node provisioning.
- A server record stores `server_id`, `node_id`, host, SSH port/user, auth type, password or private key, deploy directory, image tag, proxy port mappings, and traffic interface. API responses redact passwords, private keys, and passphrases.
- Server `auth_type` accepts `auto`, `password`, and `private_key`. For API automation, common private-key aliases such as `key`, `private-key`, `privatekey`, `ssh_key`, and `ssh-key` are normalized to `private_key`.
- Server credentials use the same `GLIDER_SETTINGS_KEY` secret storage path as Cloudflare settings. If `GLIDER_SETTINGS_KEY` is set, new SSH passwords/private keys are encrypted before they are written to MongoDB.
- Admin exposes `GET|POST /api/servers`, `GET|PUT|DELETE /api/servers/<server_id>`, `POST /api/servers/<server_id>/test-ssh`, `POST /api/servers/<server_id>/preflight-node`, `POST /api/servers/<server_id>/inspect-node`, `POST /api/servers/<server_id>/onboard-node`, `POST /api/servers/<server_id>/deploy-node`, `POST /api/servers/<server_id>/restart-node`, `POST /api/servers/<server_id>/upgrade-node`, `GET /api/jobs`, `GET /api/jobs/<job_id>`, and `GET /api/events`.
- SSH tests, node preflights, runtime inspections, node onboarding, deployments, restarts, and upgrades run as asynchronous jobs. The Servers tab shows the latest job status, structured steps, and logs; API clients can poll `/api/jobs/<job_id>`.
- Job responses include a `steps` array for provisioning diagnostics. Each step has a name, status, start/end timestamps, optional message, and optional error. Current steps cover server/job loading, SSH connection, preflight, runtime inspection, Docker installation, deployment directory preparation, file writes, image pull, token-hash save, container start, container verification, heartbeat wait, restart, and upgrade.
- Preflight is non-destructive. It connects over SSH and records host/user/kernel, Docker and Compose availability, deploy directory and compose file presence, current `glider` container state, disk/memory summary, and whether selected host proxy ports appear free or already listening.
- Inspect Node is also non-destructive. It connects over SSH, reads the selected deploy directory, current compose image, `glider` container image/status/ports, safe node `.env` fields such as `GLIDER_MODE`, `GLIDER_NODE_ID`, and `GLIDER_CENTRAL_URL`, plus disk, memory, and proxy port listener state. It stores this as a `runtime` snapshot on the server record without returning or logging `GLIDER_NODE_TOKEN`.
- Onboard Node is the recommended path for a new VPS. Admin saves the server inventory record, runs preflight, optionally installs Docker, generates a dedicated per-node token, stores only its hash in MongoDB before the remote container starts, writes the node deployment files, starts the node, and waits for a healthy heartbeat. If the heartbeat does not arrive before `wait_heartbeat_seconds`, the server is marked `heartbeat_pending` so you can inspect the job logs and node container.
- Node deployment writes a single deploy directory on the target VPS, defaulting to `/root/data/docker_data/glider`, with `.env`, `compose.yml`, `glider.conf`, `rules.d/`, `cache/`, and `certs/`.
- The generated node compose uses a fixed registry image, publishes only proxy ports such as `443` and `8443`, mounts `cache/` and `certs/`, and does not publish Admin `8444`.
- Manual Deploy Node is still available when you want to provide the plaintext node token yourself. It uses the same deployment writer and also stores the token hash before the remote container is started, so future node config/cert sync and heartbeat use the token that was pushed to the VPS.
- The deploy job can optionally install Docker with `get.docker.com` before writing the node compose. Existing Docker installations are reused.
- Restart jobs run `docker compose restart glider-node` in the server deploy directory.
- Upgrade jobs replace the compose `image:` line with the selected registry image, then run `docker compose pull && docker compose up -d`.
- Admin records audit events for server saves/deletes, SSH tests, deployment jobs, restarts, upgrades, manual DNS sync, and automatic failover switches. The Servers tab shows recent events from `/api/events`.

Domains and certificates:

- The Admin panel includes a Domains tab backed by MongoDB. It stores domain name, assigned node IDs, active node, Cloudflare zone/record metadata, DNS sync status, certificate bundle, certificate version, expiry, and renew-before days.
- Admin exposes `GET /api/domains`, `POST /api/domains`, `GET|PUT|DELETE /api/domains/<domain>`, `POST /api/domains/<domain>/dns-plan`, `POST /api/domains/<domain>/sync-dns`, `POST /api/domains/<domain>/failover-plan`, `POST /api/domains/<domain>/failover-run`, `POST /api/domains/<domain>/cert-plan`, `POST /api/domains/<domain>/issue-cert`, and `POST /api/domains/<domain>/import-cert`.
- `GET /api/domains` and `GET /api/domains/<domain>` include a read-only `runtime` object with DNS status, certificate status, renewal status, days remaining, renewal window, assigned-node certificate sync details, failover readiness, failure count, threshold, and cooldown state.
- `POST /api/domains/<domain>/dns-plan` builds a read-only Cloudflare DNS plan for the selected node. It shows the zone, record name/type, target node public IP, TTL/proxied flag, existing record content when found, and whether the sync would create, update, or leave the record unchanged.
- `POST /api/domains/<domain>/sync-dns` updates the Cloudflare DNS record to the active node's `public_ip`. It supports A and AAAA records, with TTL `1` meaning Cloudflare automatic TTL. Leave record type as `Auto` to choose A for IPv4 node IPs and AAAA for IPv6 node IPs.
- If a DNS sync attempt fails, Admin records the error but preserves the previous Cloudflare zone, record ID, record name, and last successful sync timestamp so a transient Cloudflare outage does not erase the last known working DNS state.
- `POST /api/domains/<domain>/cert-plan` builds a read-only certificate plan. It verifies the Cloudflare zone lookup and shows the ACME email/directory, `_acme-challenge` record name, current certificate version/expiry, renewal window, assigned nodes, and whether issuance would be an initial issue, renewal, or currently not due.
- `POST /api/domains/<domain>/issue-cert` uses ACME DNS-01 through Cloudflare DNS to issue a Let's Encrypt certificate, stores the fullchain and private key in MongoDB, and creates a new certificate version.
- ACME issuance waits for `_acme-challenge` TXT propagation before asking Let's Encrypt to validate. Tune this with `GLIDER_ACME_DNS_PROPAGATION_TIMEOUT` and `GLIDER_ACME_DNS_POLL_INTERVAL` on the central admin container.
- `POST /api/domains/<domain>/import-cert` stores an existing fullchain/private-key pair, validates that the key matches the certificate, reads the leaf certificate expiry, and creates a new certificate version. This is useful for testing node certificate sync before Cloudflare DNS-01 is configured.
- Domain list/detail API responses redact certificate PEM and private-key material. Full certificate material is only returned by the node certificate sync API.
- Nodes call `GET /api/node/certs?node_id=<id>` with the node bearer token. The response contains only certificates for domains assigned to that node.
- Certificate sync supports `ETag` / `If-None-Match` using `cert_version`. Nodes only send conditional requests after confirming the local certificate snapshot and files are complete. If a local certificate file is missing or differs from the snapshot, the node skips the conditional request and pulls the full certificate snapshot to repair itself.
- Nodes write certificates to `GLIDER_CERT_DIR/<domain>/fullchain.pem` and `GLIDER_CERT_DIR/<domain>/privkey.pem`, cache the certificate snapshot under `GLIDER_CACHE_DIR`, and report `cert_version` plus per-domain certificate state in heartbeats.
- Nodes skip certificate file/cache writes when the central `cert_version` is unchanged and the local certificate snapshot plus certificate files already match that version. If a certificate file is missing or differs from the snapshot, the next sync restores it from central state. This also avoids repeatedly rewriting an intentionally empty certificate snapshot.
- The Domains view compares each domain's certificate version with assigned nodes' `cert_domains` heartbeat data and shows `cert synced <n>/<total>` so you can confirm certificate delivery per node.
- The Domains view also shows certificate days remaining and renewal state such as `renew due`, `renew expired`, or `renew in <n>d`, using the same `renew_before_days` window as the automatic renewal worker.
- TLS listeners reload certificate files automatically on new handshakes when the files change, so renewed certificates do not require restarting the container.
- A TLS server listener can use `certDir=/etc/glider-certs` to choose certificates by SNI. It looks for `GLIDER_CERT_DIR/<server_name>/fullchain.pem` and `privkey.pem`, with wildcard fallback such as `*.example.com` for `www.example.com`.
- For a node that should accept domain-based TLS proxy traffic for one or more assigned domains, use a listener like:

```ini
listen=tls://:443?certDir=/etc/glider-certs,http://
listen=:8443
rules-dir=/etc/rules.d
```

  The container must publish `443:443` for this SNI entry point. After importing or issuing a test certificate, you can verify the path without changing public DNS by resolving the test name locally:

```bash
curl --proxy-insecure \
  --proxy https://user1:pass1@proxy.example.com:443 \
  --resolve proxy.example.com:443:<node-ip> \
  https://ipinfo.io/json
```

  A successful response proves the node accepted TLS on `443`, selected the synced certificate by SNI, authenticated the proxy user, and routed traffic through the user's assigned rule.

- The older fixed-certificate form remains supported for single-domain or manually managed deployments:

```ini
listen=tls://:443?cert=/etc/glider-certs/proxy.example.com/fullchain.pem&key=/etc/glider-certs/proxy.example.com/privkey.pem,http://
```

Cloudflare token:

- Use a Cloudflare API Token, not the legacy Global API Key. The Global API Key is account-wide; an API Token can be restricted by permission and zone.
- A Cloudflare Account API Token is still an API Token. It is owned by the Cloudflare account instead of a single user, which makes it a good fit for long-running admin services. If you use an account-owned token, enter the Cloudflare account ID in the Admin panel so token verification uses the account token endpoint.
- A user-owned API Token also works. For a user-owned token, leave account ID empty so verification uses the user token endpoint.
- Scope the token to the specific zone whenever possible.
- Required permissions: `Zone:Read` and `DNS:Edit` for the selected zone. `Zone:Read` lets the admin find the zone when `zone_id` is not entered manually. `DNS:Edit` lets the admin create/update A, AAAA, and `_acme-challenge` TXT records for DNS-01 validation.
- Configure the token from the Admin panel in `Domains -> Cloudflare Settings`. The panel stores it in MongoDB, returns only a masked value to the browser, and uses it for DNS sync, failover, and certificate issuance/renewal.
- Use `Verify Token` in that panel before DNS or certificate work. Enter a `Zone test domain` to verify the token can read the matching zone; enable `DNS edit test` when you also want the admin to create and immediately delete a temporary `_glider-check-*` TXT record to prove `DNS:Edit`.
- Set `GLIDER_SETTINGS_KEY` on the central admin container to encrypt stored settings before writing them to MongoDB. Keep the same key across admin redeploys, or previously encrypted settings cannot be decrypted.
- `GLIDER_CLOUDFLARE_API_TOKEN`, `GLIDER_CLOUDFLARE_ACCOUNT_ID`, and `GLIDER_ACME_EMAIL` are still supported as central `.env` fallbacks. Never put Cloudflare credentials in node `.env` or commit them.

Real-domain onboarding check:

- After saving Cloudflare settings in Admin and confirming that the node heartbeat is online, run the helper below from a trusted machine. By default it verifies Admin auth, node heartbeat, Cloudflare token zone access, and builds DNS/certificate preview plans for an already saved domain. It does not save the domain, update DNS, or issue a certificate unless you pass the explicit write flags.

```bash
python3 deploy/scripts/domain_onboarding_check.py \
  --admin-url http://<admin-ip>:8444 \
  --admin-token "$GLIDER_ADMIN_TOKEN" \
  --domain proxy.example.com \
  --node-id zgo \
  --acme-email admin@example.com
```

- To save Cloudflare settings from the CLI instead of the Admin UI, pass `--save-cloudflare-settings` with either `--prompt-cloudflare-token`, `--cloudflare-token`, or `GLIDER_CLOUDFLARE_API_TOKEN`. The script does not print the token. For account-owned Cloudflare tokens, also pass `--cloudflare-account-id <account-id>`. Existing account ID, ACME email, and ACME directory values are preserved unless you pass a replacement value or one of the explicit clear flags. Add `--dns-edit-test` when you want the script to prove `DNS:Edit` by creating and deleting a temporary TXT record.
- Add `--save-domain` to create or update the domain/node assignment before previewing DNS and certificate plans.
- Add `--issue-cert` to request or renew the Let's Encrypt certificate with ACME DNS-01. Add `--sync-dns` after the certificate is issued and the node heartbeat reports the matching domain certificate version. DNS sync refuses to point a TLS domain at a node that is stale, unassigned, missing a public IP, or missing the current certificate version.

Failover behavior:

- When `failover_enabled` is true, the admin worker checks assigned node heartbeats every `GLIDER_DOMAIN_RECONCILE_INTERVAL`.
- A node is considered online for failover when its latest heartbeat is within 90 seconds, has no node error, and does not have a fresh Admin-side proxy health error.
- Domains have a `failover_policy` with `fail_threshold`, `cooldown_seconds`, `manual_lock`, `auto_failback`, and `primary_node_id`. If `primary_node_id` is empty, Admin treats the first assigned node as the primary.
- Admin increments `failover_state.active_failure_count` while the active node is unhealthy. DNS changes only happen after the consecutive failure count reaches `fail_threshold`.
- After a successful DNS switch, Admin resets the failure count and sets `cooldown_until`. The failover worker will not switch that domain again until the cooldown expires.
- When `manual_lock` is true, automatic switching is blocked and the current `active_node_id` is treated as pinned. You can still manually choose a node and run `Sync DNS`.
- When `auto_failback` is true, the active node is healthy, the primary node has recovered, the primary node is certificate-ready, and the domain is outside cooldown, Admin switches DNS back to the primary node and starts a new cooldown window.
- Failover candidates must be assigned to the domain, have a fresh heartbeat, pass the latest fresh proxy health state, have a public IP, and, when the domain has a certificate version, report the same unexpired certificate version in heartbeat.
- On a failover, Admin updates the Cloudflare A/AAAA record to the selected node's heartbeat `public_ip` and records the from-node, to-node, switch time, cooldown, and last reason in `failover_state`.
- Use `Preview Failover` or `POST /api/domains/<domain>/failover-plan` to evaluate the current state without writing failover state or changing DNS. Use `Run Failover` or `POST /api/domains/<domain>/failover-run` to run the same state machine once immediately; it records state changes and, when the threshold/cooldown/manual-lock rules allow a switch, updates Cloudflare DNS and the active node.
- The certificate worker checks managed domains every `GLIDER_CERT_RENEW_INTERVAL`. If a certificate is missing or within `renew_before_days`, it renews with ACME DNS-01 and increments the certificate version.
- Automatic renewal requires a Cloudflare token and ACME email configured either in the Admin panel or through the central `.env` fallback.
- Cloudflare Load Balancing can also be used if you want Cloudflare-managed health checks instead of DNS-record switching inside Glider.

Formal deployment flow:

1. Publish a fixed image tag to GHCR, for example `ghcr.io/FerryboatSeranade/glider:v2026.06.13`.
2. Run one central Admin deployment from `/root/data/docker_data/glider-admin` with `GLIDER_MODE=admin`, MongoDB, `GLIDER_ADMIN_TOKEN`, `GLIDER_NODE_TOKEN`, and `GLIDER_SETTINGS_KEY`.
3. Expose only Admin `8444` on the central host, preferably behind VPN, Cloudflare Access, or an authenticated reverse proxy.
4. In Admin, save Cloudflare settings and verify the token against the target zone.
5. In `Servers`, add each new VPS SSH credential, test SSH, then run `Onboard Node`. Use `Deploy Node` only when you need to provide a specific plaintext node token yourself.
6. Run `Inspect Node` after onboarding or upgrades to confirm the remote compose image, node mode, node ID, central URL, container status, and published proxy ports match the intended deployment.
7. Wait for the node heartbeat to appear in `Nodes`; confirm it is online, has the expected public IP, and is synced to the central `config_version`.
8. In `Domains`, assign a domain to multiple nodes, choose the active node, issue or import the certificate, wait until assigned nodes report the matching `cert_version`, then run `Sync DNS`.
9. Enable failover with a threshold and cooldown. Use manual lock when you want DNS pinned during maintenance.
10. Use `Preview Failover` to confirm the current active node, target candidate, threshold, cooldown, and block reason. Use `Run Failover` for an immediate one-shot check instead of waiting for the next reconcile tick.

Traffic notes:

- Node total traffic is read from `/sys/class/net/<interface>/statistics/*_bytes` by default. You can still use `vnstat` operationally for host-level auditing.
- TCP user-level, rule-level, and dialer/line-level traffic is counted inside glider's proxy path and included in node heartbeats under `traffic.users`, `traffic.rules`, and `traffic.dialers`.
- UDP traffic is still reported only in the node total counters. `vnstat` cannot split traffic by glider user.

Migration from `glider + glider2` to one node deploy directory:

1. Build and publish an image, for example `ghcr.io/ferryboatseranade/glider:v2026.06.06`.
2. Stop the old `glider2` container.
3. Create `/root/data/docker_data/glider` as the only deploy directory.
4. Move the runtime files from `glider2` into it: `compose.yml`, `.env`, `glider.conf`, `rules.d/`, and optionally create `cache/`.
5. Replace `build: ../glider` with the fixed `image:` tag and remove the source checkout from the node after verification.
6. For ordinary nodes, remove the `8444:8444` port mapping and set `GLIDER_MODE=node`.
7. Start with `docker compose up -d` and verify that only `443` and `8443` are published on nodes.

Central migration on a host that already has `/root/data/docker_data/glider`:

1. Create `/root/data/docker_data/glider-admin`.
2. Copy [deploy/admin.compose.yml](deploy/admin.compose.yml), [deploy/admin.env.example](deploy/admin.env.example), and [deploy/admin.glider.conf.example](deploy/admin.glider.conf.example) into it as `compose.yml`, `.env`, and `glider.conf`.
3. Create `rules.d/`.
4. Fill in `.env` secrets and the fixed image tag.
5. Start with `docker compose up -d` and expose only `8444`.

Security:

- Open Admin only on the central host, ideally behind VPN, Cloudflare Access, or authenticated reverse proxy.
- Use `GLIDER_ADMIN_ALLOWED_CIDRS` to add a process-level source IP/CIDR allowlist for Web Admin and Admin APIs. It accepts comma, space, or newline separated IPs/CIDRs. Node sync APIs still authenticate with node tokens and are not blocked by this Admin allowlist.
- Set `GLIDER_ADMIN_TRUST_PROXY_HEADERS=true` only when requests reach Admin through your own trusted reverse proxy; otherwise client-supplied forwarding headers are ignored for Admin allowlist checks and heartbeat public-IP inference.
- Put `GLIDER_ADMIN_TOKEN`, `GLIDER_NODE_TOKEN`, `GLIDER_SETTINGS_KEY`, and MongoDB URI in `.env`; do not commit live `.env` files or deploy directories.
- Use `GLIDER_NODE_TOKEN` as a bootstrap secret, then prefer dedicated per-node tokens for long-lived VPS nodes. Rotate or clear a node token if that node is decommissioned or suspected compromised.
- MongoDB stores certificate private keys for managed domains. Keep MongoDB access restricted and back it up like other secret-bearing infrastructure.
- Node cache may contain user passwords and certificate private keys. Keep `cache/` and `certs/` private; snapshots and certificate files are written with `0600` permissions.

Test plan:

- `go test ./...` covers config apply, version stability, local cache boot, central sync, central unavailable behavior, and reload failure preserving old config.
- Reload failure tests assert both memory and disk safety: failed config apply keeps the previous `rules.d` files, and node sync does not overwrite `cache/config_snapshot.json` with a config that failed to apply.
- Admin mode smoke test: run `GLIDER_MODE=admin GLIDER_MONGO_URI=... GLIDER_ADMIN_TOKEN=... GLIDER_NODE_TOKEN=... glider -admin :8444` and verify `/api/users` requires the admin token.
- Node mode smoke test: run with `GLIDER_MODE=node` and a proxy listener, verify no `8444` process or Docker port is exposed.
- Cache boot test: start a node with `cache/config_snapshot.json` present and central URL unavailable; proxy should still start from cached config.
- Version-change test: update a rule/user in Mongo, fetch `/api/node/config`, and verify the node reloads only when `config_version` changes.
- Failure test: publish a config referencing a missing rule; node should report the error in heartbeat, keep the previous working version, keep the old `rules.d` contents, and leave the old cached snapshot in place.
- Certificate sync test: assign a domain to a node, issue/import a cert, fetch `/api/node/certs`, and verify files appear under `GLIDER_CERT_DIR/<domain>/`.
- DNS sync test: use a Cloudflare API token scoped to a test zone, sync DNS to a selected node, and verify the A/AAAA record points at the node heartbeat `public_ip`.
- DNS failure test: simulate Cloudflare returning an error and verify Admin keeps the previous record metadata while surfacing the new error status.
- Server inventory test: save a server with SSH password/private-key fields and verify Admin API responses expose only `has_password` / `has_private_key` flags, never plaintext secrets.
- Provision render test: verify generated node `.env`, `compose.yml`, and `glider.conf` contain `GLIDER_MODE=node`, the selected image tag, proxy ports, cache/cert mounts, and no Admin port.
- Provisioning job steps test: run or inspect a provisioning job and verify `/api/jobs/<job_id>` includes structured `steps` showing which phase is running, succeeded, or failed.
- Runtime inspect test: call `POST /api/servers/<server_id>/inspect-node` for a deployed node and verify the server `runtime` snapshot contains the expected compose image, `GLIDER_MODE=node`, node ID, central URL, container status, and proxy port listeners without exposing `GLIDER_NODE_TOKEN`.
- Node proxy health test: publish a working test user, verify Admin stores `proxy_status=ok` with the exit IP/ASN for a reachable node, then break the proxy port and verify a fresh `proxy_status=error` blocks failover until the probe result becomes stale or recovers.
- Failover debounce test: mark the active node stale and verify no DNS switch happens before `fail_threshold`, then verify the next failed check selects a healthy assigned standby and sets `cooldown_until`.
- Failover lock test: set `manual_lock=true` and verify automatic failover is blocked even when the active node is unhealthy and a standby is ready.
- Manual failover API test: call `/api/domains/<domain>/failover-plan` and verify it reports the same state-machine decision as the background worker without changing state; call `/failover-run` and verify it records state changes and only updates DNS when `should_switch=true`.

## Service

- dhcpd / dhcpd-failover:
  - service=dhcpd,INTERFACE,START_IP,END_IP,LEASE_MINUTES[,MAC=IP,MAC=IP...]
    - service=dhcpd,eth1,192.168.1.100,192.168.1.199,720,fc:23:34:9e:25:01=192.168.1.101
    - service=dhcpd-failover,eth2,192.168.2.100,192.168.2.199,720
  - note: `dhcpd-failover` only serves requests when there's no other dhcp server exists in lan
    - detect interval: 1min

## Linux Daemon

- systemd: [https://github.com/nadoo/glider/tree/main/systemd](https://github.com/nadoo/glider/tree/main/systemd)

- <details> <summary>docker: click to see details</summary>

  - run glider (config file path: /etc/glider/glider.conf)
    ```
    docker run -d --name glider --net host --restart=always \
      -v /etc/glider:/etc/glider \
      -v /etc/localtime:/etc/localtime:ro \
      nadoo/glider -config=/etc/glider/glider.conf
    ```
  - run watchtower if you need auto update
    ```
    docker run -d --name watchtower --restart=always \
      -v /var/run/docker.sock:/var/run/docker.sock \
      containrrr/watchtower --interval 21600 --cleanup \
      glider
    ```
  - open udp ports if you need udp nat fullcone
    ```
    iptables -I INPUT -p udp -m udp --dport 1024:65535 -j ACCEPT
    ```
  
  </details>


## Customize Build

<details><summary>You can customize and build glider if you want a smaller binary (click to see details)</summary>


1. Clone the source code:
  ```bash
  git clone https://github.com/nadoo/glider && cd glider
  ```
2. Customize features:

  ```bash
  open `feature.go` & `feature_linux.go`, comment out the packages you don't need
  // _ "github.com/nadoo/glider/proxy/kcp"
  ```

3. Build it:
  ```bash
  go build -v -ldflags "-s -w"
  ```

</details>

## Proxy & Protocol Chains
<details><summary>In glider, you can easily chain several proxy servers or protocols together (click to see details)</summary>

- Chain proxy servers:

  ```bash
  forward=http://1.1.1.1:80,socks5://2.2.2.2:1080,ss://method:pass@3.3.3.3:8443@
  ```

- Chain protocols: https proxy (http over tls)

  ```bash
  forward=tls://server.com:443,http://
  ```

- Chain protocols: vmess over ws over tls

  ```bash
  forward=tls://server.com:443,ws://,vmess://5a146038-0b56-4e95-b1dc-5c6f5a32cd98@?alterID=2
  ```

- Chain protocols and servers:

  ``` bash
  forward=socks5://1.1.1.1:1080,tls://server.com:443,vmess://5a146038-0b56-4e95-b1dc-5c6f5a32cd98@?alterID=2
  ```

- Chain protocols in listener: https proxy server

  ``` bash
  listen=tls://:443?cert=crtFilePath&key=keyFilePath,http://
  ```

- Chain protocols in listener: http over smux over websocket proxy server

  ``` bash
  listen=ws://:10000,smux://,http://
  ```

</details>

## Links

- [ipset](https://github.com/nadoo/ipset): netlink ipset package for Go.
- [conflag](https://github.com/nadoo/conflag): a drop-in replacement for Go's standard flag package with config file support.
- [ArchLinux](https://archlinux.org/packages/extra/x86_64/glider): a great linux distribution with glider pre-built package.
- [urlencode](https://www.w3schools.com/tags/ref_urlencode.asp): you should encode special characters in scheme url. e.g., `@`->`%40`
