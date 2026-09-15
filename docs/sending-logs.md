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

=== "EasyWAF"

    EasyWAF ships its event log itself: point `syslog_host` / `syslog_port` in its `config.toml` at EasyLog, register the appliance as a source of type **EasyWAF**, and every proxied request arrives as one line carrying its verdict, score and the rules that fired.

    Delivery is deliberately fire-and-forget — EasyWAF drops lines rather than blocking its own request path — so treat the counts as what arrived, not as a guaranteed tally of every request served. Several appliances can send to one EasyLog; each event keeps the address it came from, which is what the per-appliance table is built on.

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
