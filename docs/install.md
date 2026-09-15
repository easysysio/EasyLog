# Installation

EasyLog ships as a single binary and installs a **service** that starts on boot.
Install it from the EasySYS package repository so upgrades come through your
package manager. Packages are published for **x86_64** and **arm64**; your
package manager picks the right one.

=== "Debian / Ubuntu"

    ```bash
    # Add the EasyLog repository (signed)
    curl -fsSL https://repo.easysys.io/easylog/stable/debian/key.gpg \
      | sudo gpg --dearmor -o /usr/share/keyrings/easysys.gpg
    echo "deb [signed-by=/usr/share/keyrings/easysys.gpg] https://repo.easysys.io/easylog/stable/debian ./" \
      | sudo tee /etc/apt/sources.list.d/easylog.list

    sudo apt update
    sudo apt install easylog
    sudo systemctl enable --now easylog
    ```

=== "RHEL / Fedora"

    ```bash
    sudo tee /etc/yum.repos.d/easylog.repo >/dev/null <<'EOF'
    [easylog]
    name=EasyLog
    baseurl=https://repo.easysys.io/easylog/stable/redhat
    enabled=1
    gpgcheck=1
    gpgkey=https://repo.easysys.io/easylog/stable/redhat/key.gpg
    EOF

    sudo dnf install easylog
    sudo systemctl enable --now easylog
    ```

=== "openSUSE / SLES"

    ```bash
    sudo zypper addrepo -fg https://repo.easysys.io/easylog/stable/redhat easylog
    sudo zypper install easylog
    sudo systemctl enable --now easylog
    ```

=== "Manual download"

    For air-gapped hosts, grab the `.deb` or `.rpm` for your architecture from the
    [releases page](https://github.com/easysysio/EasyLog/releases):

    ```bash
    sudo dpkg -i easylog_*_amd64.deb     # or _arm64.deb
    sudo rpm  -i easylog-*.x86_64.rpm    # or .aarch64.rpm
    sudo systemctl enable --now easylog
    ```

    Upgrades then mean downloading the next package by hand — the repository is
    the easier path where the host has network access.

The package installs the binary to `/usr/bin/easylog`, a default config to `/etc/easylog/easylog.toml`, and a systemd unit; the database lives in `/var/lib/easylog`. The service runs as root (standard for a syslog collector binding port 514).

Then open `http://<host>:3000/` — on first run you'll be prompted to **create the admin account**, after which the UI requires login.

Next: [register a source and forward its logs](sending-logs.md).
