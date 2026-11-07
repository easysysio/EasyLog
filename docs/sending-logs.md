# Sending logs

There are two steps: tell EasyLog which host sends which log type, then forward the logs.

## 1. Register the source

In the web UI, open **Sources** (`/sources`) and add the sending host's **IP address** with its **log type**, any of the types listed under [Supported log types](reference.md#supported-log-types). EasyLog routes incoming syslog by source IP — traffic from unregistered hosts is dropped.

## 2. Forward the logs

Point the host's log file at EasyLog's syslog port with `rsyslog`'s `imfile` module. Polling mode is recommended for reliability inside containers.

=== "Apache / Nginx"

    `/etc/rsyslog.d/60-easylog.conf` on the web server:

    ```rsyslog
    module(load="imfile" mode="polling" pollingInterval="2")

    input(type="imfile"
          File="/var/log/apache2/access.log"   # nginx: /var/log/nginx/access.log
          Tag="apache"
          ruleset="easylog_forward")

    ruleset(name="easylog_forward") {
        action(type="omfwd" target="EASYLOG_IP" port="514"
               protocol="udp" template="RSYSLOG_ForwardFormat")
    }
    ```

=== "Traefik"

    Enable JSON access logs in `traefik.yml`:

    ```yaml
    accessLog:
      filePath: /var/log/traefik/access.log
      format: json
    ```

    …then forward `/var/log/traefik/access.log` with the same `imfile` config as above, using `Tag="traefik"`.

=== "Caddy"

    Enable the JSON access log for a site in your `Caddyfile`:

    ```caddyfile
    example.com {
        log {
            output file /var/log/caddy/access.log
            format json
        }
    }
    ```

    …then forward `/var/log/caddy/access.log` with the same `imfile` config as above, using `Tag="caddy"`. Caddy's own lifecycle messages in that stream are ignored by the parser.

=== "Anything else"

    Set the source's type to **General logs** and forward the file or stream as usual — EasyLog stores each line exactly as it arrives, with no parser involved. Useful for a device EasyLog doesn't understand yet, or just to see what a host is actually sending before deciding what to do with it.

    Note this is a type you choose per source: traffic from hosts you haven't registered is still ignored, and a line a *typed* source's parser rejects is still dropped rather than falling through to here.

=== "Cisco ASA"

    On the ASA, send syslog straight to EasyLog:

    ```
    logging enable
    logging timestamp
    logging trap informational
    logging host inside EASYLOG_IP
    ```

    EasyLog reads the connection and access-decision messages (106023, 106100, 106001, 302013–302016) and ignores the rest of the ASA's chatter.

=== "Palo Alto"

    In **Device → Server Profiles → Syslog**, add a profile pointing at `EASYLOG_IP:514` (UDP), then attach it to a **Log Forwarding** profile for **Traffic** logs and reference that profile from your security rules. EasyLog parses TRAFFIC records; THREAT, SYSTEM and CONFIG logs are ignored.

=== "UniFi Gateway"

    UniFi gateways (UDM, UDM Pro/SE, UCG, UXG and the older USG) send two kinds of security event, and EasyLog reads both onto one dashboard: **firewall-rule hits** (what a rule blocked or allowed) and **IDS/IPS threat detections**. Both are set up in the UniFi Network application; menu names move between versions.

    1. **Send syslog to EasyLog.** Find **Activity Logging (Syslog)** (under CyberSecure → Traffic Logging, or System → Advanced, depending on version), choose **SIEM Server**, and enter `EASYLOG_IP` and port `514`.
    2. **Choose the contents.** Under **Contents**, keep **Firewall Default Policy** (UniFi's built-in "block all" rules) and **Security Detections** (IDS/IPS). Client, device, access-point, switch and update events carry no traffic, so EasyLog only counts them as unparsed — leave them out to save the noise.
    3. **Log your own rules.** Edit each firewall policy whose hits you want to see and turn on **Syslog Logging**. Block rules are the usual place to start.

    Register the gateway's address — the one it sends from, which may be on a different network from its management address — as a source of type **UniFi Gateway**.

    Each firewall-rule hit becomes one event: its verdict (accept, or drop / reject / block), the rule — by its UniFi name (`Block All Traffic`; UniFi cuts long names short to fit the firewall's log label, so some arrive as `Block All Traff`), or by chain and number such as `WAN_IN-2000` on firmware without names — and the chain (`WAN_LOCAL` for traffic aimed at the gateway itself, `DMZ_LAN` from one zone to another, and so on). IPv4 and IPv6 alike.

    Each threat detection arrives in CEF and becomes one event too: source and destination with ports, the application (`SMTP`, `HTTPS`), the IPS signature as the rule, "Threat Detected" in the chain's place, the zone, and the time the gateway recorded. An IDS in detect-only mode reports these as **allowed** — the traffic got through — and they only show as denies once **Intrusion Prevention** blocks them.

    !!! note "Discovery broadcasts are skipped"
        The gateway announces itself on every network it serves with a UniFi discovery broadcast (UDP port `10001` to `255.255.255.255`), and each network's "Block All" rule logs it — several times a minute. EasyLog drops exactly those lines (they count as unparsed), so they don't bury the blocks worth seeing. Other broadcasts, and ordinary traffic to port 10001, are kept.

=== "EasyWAF"

    EasyWAF ships its event log itself: point `syslog_host` / `syslog_port` in its `config.toml` at EasyLog, register the appliance as a source of type **EasyWAF**, and every proxied request arrives as one line carrying its verdict, score and the rules that fired.

    Delivery is deliberately fire-and-forget — EasyWAF drops lines rather than blocking its own request path — so treat the counts as what arrived, not as a guaranteed tally of every request served. Several appliances can send to one EasyLog; each event keeps the address it came from, which is what the per-appliance table is built on.

=== "Linux"

    Forward the server's whole syslog stream — EasyLog keeps every line, so there is nothing to filter on the sending side. Register the server as a source of type **Linux**, then on the server create `/etc/rsyslog.d/90-easylog.conf`:

    ```
    # UDP; use @@EASYLOG_IP:514 for TCP
    *.* @EASYLOG_IP:514
    ```

    …and `sudo systemctl restart rsyslog`. On a journald-only system, install `rsyslog` first (it reads the journal), or set `ForwardToSyslog=yes` in `/etc/systemd/journald.conf`.

    Every line is stored with its program and PID. SSH logins (accepted, failed, invalid user, dropped before authentication), sudo and su (including refusals), PAM authentication failures for other services, and account changes (`useradd`, `usermod`, `passwd`, …) are also read into structured fields for the dashboard. Both the classic BSD syslog header and RFC 5424 work.

    A central rsyslog relay forwarding many servers from one address works too: the dashboard groups by the hostname each server put in its syslog header.

=== "HAProxy"

    HAProxy speaks syslog natively — no `imfile` needed. In `haproxy.cfg`:

    ```haproxy
    global
        log EASYLOG_IP:514 local0

    defaults
        log     global
        option  httplog
    ```

    `option httplog` is required: the TCP log format carries no status code or request line, so those lines are dropped.

Apply and restart:

```bash
sudo rsyslogd -N1            # validate config
sudo systemctl restart rsyslog
```

!!! warning "Log format & reverse proxies"
    EasyLog parses both **Common** and **Combined** access-log formats — Nginx's default `combined` and Apache's `combined`/`common` all work out of the box. If a host sits behind a reverse proxy, configure it to log the real client IP (e.g. `mod_remoteip` / `X-Forwarded-For`) so the dashboards show visitors rather than the proxy.
