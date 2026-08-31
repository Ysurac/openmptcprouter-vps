# OpenMPTCProuter VPS — User Manual

This is the server side ("VPS") of [OpenMPTCProuter](https://www.openmptcprouter.com/): a piece of
software that runs on a cheap VPS and terminates the tunnels your OpenMPTCProuter router aggregates
its internet connections through. This manual covers installing, configuring, and operating that
VPS. For internal architecture and contributor notes, see [TECHNICAL.md](TECHNICAL.md).

## 1. What gets installed

A single install script sets up, on a fresh Debian/Ubuntu box:

- An MPTCP-enabled kernel
- One or more tunnel/proxy endpoints your router can connect through: Shadowsocks(-libev and Go),
  V2Ray, Xray (incl. VLESS Reality), Glorytun (TCP and UDP), MLVPN, UBOND, DSVPN, WireGuard, MQVPN,
  OpenVPN (with up to 8 "bonding" instances), SoftEther, VXLAN, and 6in4 (IPv6-in-IPv4)
- `omr-admin`, the REST API the router's web UI talks to for provisioning and monitoring
- A native nftables firewall ruleset (replaces the older Shorewall/Shorewall6 setup)
- Fail2ban jails protecting SSH and OpenVPN
- `omr-service`, a watchdog that keeps tunnels alive

You don't need to enable everything — most tunnel types are individually toggled (see §3).

## 2. Requirements

- **OS**: Debian 9–13, 64-bit (amd64 or arm64)
- **Kernel**: the installer manages this for you — supported MPTCP kernel lines are `5.4, 6.1, 6.6,
  6.10, 6.11, 6.12, 6.18` (default `6.18`)
- Run as **root**
- Outbound internet access during install (packages/binaries are fetched from
  `repo.openmptcprouter.com` and GitHub)

## 3. Installing

The simplest install, run as root on a fresh VPS:

```sh
wget -O - http://www.openmptcprouter.com/server/debian.sh | sh
```

This is fully non-interactive — there are no prompts. Everything is controlled by environment
variables read at the top of the script, each with a sensible default. To customize, export
variables before running it, e.g.:

```sh
MQVPN=no WIREGUARD=no SOFTETHERVPN=yes wget -O - http://www.openmptcprouter.com/server/debian.sh | sh
```

### Commonly-adjusted options

| Variable | Default | Effect |
|---|---|---|
| `KERNEL` | `6.18` | MPTCP kernel line to install |
| `SHADOWSOCKS` / `SHADOWSOCKS_GO` | `yes` | Enable Shadowsocks-libev / Shadowsocks-Go (2022 edition) |
| `V2RAY` | `yes` | Enable V2Ray |
| `XRAY` | `yes` | Enable Xray (incl. VLESS Reality) |
| `MLVPN` | `yes` | Enable MLVPN |
| `UBOND` | `no` | Enable UBOND |
| `MQVPN` | `yes` | Enable MQVPN |
| `OPENVPN` / `OPENVPN_BONDING` | `yes` / `yes` | Enable OpenVPN, and its 8-way bonding tunnels |
| `SOFTETHERVPN` | `no` | Enable SoftEther VPN |
| `DSVPN` | `yes` | Enable DSVPN |
| `WIREGUARD` | `yes` | Enable WireGuard |
| `FAIL2BAN` | `yes` | Install and configure fail2ban |
| `OMR_ADMIN` | `yes` | Install the `omr-admin` API server (needed by the router's web UI) |
| `OMR_METRICS` | `no` | Install the metrics collector |
| `OMR_AI` | `no` | Install the AI-assisted forecasting/decision add-on |
| `BPFTUNE` | `no` | Enable `bpftune` |
| `SOURCES` | `no` | Build tunnel binaries from source instead of using prebuilt packages |
| `REINSTALL` | `yes` | If `no`, the script exits early when the same version is already installed |
| `TLS` | `yes` | Request an ACME TLS certificate for V2Ray/Xray |
| `INTERFACE` / `INTERFACE6` | auto-detected | Force a specific network interface |
| `VPS_DOMAIN` / `VPS_PUBLIC_IP` | auto-detected | Override if auto-detection picks the wrong address |

Secrets (`SHADOWSOCKS_PASS`, `GLORYTUN_PASS`, `MQVPN_KEY`, `OMR_ADMIN_PASS`, `PSK`, etc.) are
randomly generated if you don't set them — you normally don't need to.

> All the `*-x86_64.sh` and `ubuntu*.sh` files in the repo root are the same script
> (`debian9-x86_64.sh`) via symlink — pick whichever filename matches your OS out of habit, they
> behave identically. There is no `debian9-x86_64-mlvpn.sh` in the current version despite older
> documentation mentioning it.

## 4. After install

The script prints your generated keys/ports and also saves them to:

```
/root/openmptcprouter_config.txt
```

**Keep this file safe** — it's what you paste into the router's setup wizard. Key ports (also
shown in `/etc/motd`):

| Service | Port |
|---|---|
| SSH | 65222 (moved from 22) |
| omr-admin API | 65500 |
| Shadowsocks | 65101 |
| Glorytun | 65001 |
| DSVPN | 65401 |
| MLVPN | 65201+ |
| UBOND | 65251+ |
| MQVPN | 65443 |
| WireGuard (server / client) | 65311 / 65312 |
| OpenVPN | 65301 |
| SoftEther | 65390 |

A watchdog (`omr-service`, always installed) polls every 10 seconds and restarts any tunnel
service whose process has died or whose remote end has stopped answering, so you shouldn't need to
babysit individual tunnels.

## 5. Updating

To re-run the installer against an already-installed VPS, set `UPDATE=yes` (the default) and run
the same command again. On an existing install this:

- Detects it's an update (via `/etc/motd` or `/root/openmptcprouter_config.txt`)
- **Does not regenerate keys** — package versions and service units are refreshed, then services
  are restarted
- **Does overwrite the nftables firewall files** (`/etc/nftables.conf` and everything under
  `/etc/nftables/`) with the shipped defaults every time, including on an update — see §7. This is
  safe for the per-user rules `omr-admin` manages (it re-syncs those right after the update
  restarts it), but any rule you added by hand won't survive an update.
- If `REINSTALL=no` and you're already on the current version, it exits immediately without doing
  anything

There's also an automatic path: `omr-update.service` (a systemd oneshot unit) checks for a marker
file under `/etc/openmptcprouter-vps-admin/` and re-runs the installer for you — this is what
fires after a Debian package upgrade of `omr-server`.

## 6. Managing tunnels manually

Every tunnel type is a normal systemd service/template, so standard tooling works:

```sh
systemctl status glorytun-udp@tun0
systemctl restart mqvpn.service
systemctl status omr-vxlan@user0
journalctl -u omr-admin -f
```

VXLAN and 6in4 tunnels are per-user template instances
(`omr-vxlan@<instance>.service`, `omr6in4@<instance>.service`); their config files live under
`/etc/openmptcprouter-vps-admin/omr-vxlan/` and `/etc/openmptcprouter-vps-admin/omr-6in4/`
respectively, and are managed by `omr-admin`, not edited by hand under normal operation.

## 7. Firewall

A native nftables ruleset is installed to `/etc/nftables.conf` (which just `include`s
`/etc/nftables/omr-vars.nft` and `/etc/nftables/omr.nft`). This replaced the older Shorewall/
Shorewall6 setup — if you're upgrading from an older install, Shorewall is masked and disabled and
`shorewall`/`shorewall6` are no longer used, even though their old config directories
(`/etc/shorewall`, `/etc/shorewall6`) are left in place.

The default policy allows tunnel traffic (`vpn`) to reach the internet (`net`) and the box itself,
blocks unsolicited inbound from `net`, and blocks lateral traffic between tunnel endpoints
(disable that last one with the router's "client to client" option, if you need it). Per-user
opened/redirected ports, GRE tunnel NAT, and DSCP marking are all managed for you by `omr-admin` —
you shouldn't normally need to hand-edit the nftables files.

If you do need a custom rule — most commonly to open a port for a service running directly on the
VPS itself — note that **every re-run of the installer (including a plain update) fully overwrites
`/etc/nftables.conf`, `/etc/nftables/omr-vars.nft` and `/etc/nftables/omr.nft`** from the package's
shipped copies — unlike the old Shorewall setup, there's no preservation of locally-edited files
across an update. Don't hand-edit those three files; instead drop your own `.nft` file(s) into
`/etc/nftables/custom.d/` (created empty by the installer, and never written to or emptied by it —
anything you put there survives every update). It's glob-`include`d last, so your file(s) can `add
rule` into any chain, including two the installer sets aside just for this:

- `custom_accept` — same shape as the per-user `user_accept` chain `omr-admin` manages, but never
  touched by it: `add rule inet omr custom_accept tcp dport 8080 accept`.
- `custom_dnat_bypass` — checked *before* `omr-admin`'s per-user DNAT redirects and the bulk
  1-64999→router toggle, so a matching rule here keeps traffic addressed to the VPS instead of
  being redirected into a tunnel: `add rule inet omr custom_dnat_bypass tcp dport 8080 accept`.

Without that second rule, a DNAT redirect covering the same port (per-user, or the bulk toggle)
would still steal the traffic before it ever reaches `custom_accept` — previously the only fix was
editing `omr-admin-config.json` by hand to remove/narrow the conflicting redirect (see
[TECHNICAL.md §7](TECHNICAL.md#7-firewall-nftablesconf-nftables--migrated-off-shorewall) and
[issue #4356](https://github.com/Ysurac/openmptcprouter/issues/4356)). A single file covering both
chains is now enough — no `omr-admin-config.json` edits needed. After adding or changing a file
there, apply it with `systemctl reload nftables` (or `restart`; no need to touch `omr-admin`, since
these two chains are never among the ones it flushes/rebuilds).

## 8. Fail2ban

If `FAIL2BAN=yes` (default), fail2ban is configured to watch:

- SSH (default fail2ban `sshd` jail)
- OpenVPN's TLS handshake port (both TCP and UDP instances), banning on repeated
  `TLS Auth Error` / `VERIFY ERROR` / handshake failures
- The omr-admin API (port 65500), banning on repeated failed logins to `/token` (used by the
  router) or `/login_basic` (used by the `/docs` page) — 6 failures bans the source IP
- Xray and V2Ray, banning on repeated rejected inbound connections (invalid user/UUID, malformed
  requests, port scanning) — 6 rejections bans the source IP
- Shadowsocks-Go, banning on repeated failed Shadowsocks-2022 handshakes (wrong key) — 6 failures
  bans the source IP

**Not covered, by design**: Glorytun (TCP and UDP) and MQVPN don't get a fail2ban jail. Their
daemons never log the remote peer's IP address anywhere on a failed key exchange/PSK check
(verified against their source) — there is nothing in their logs for fail2ban to match against. In
practice this matters less for these than for password-style logins: their shared secrets are
long random keys exchanged out of band, not something an attacker can meaningfully guess by
repeated connection attempts.

## 9. Troubleshooting

- **Tunnel keeps dropping**: check `journalctl -u omr-service` for restart log lines — the watchdog
  logs which tunnel it restarted and why (missing process vs. no ping response).
- **Router can't reach the admin API**: confirm `omr-admin` is listening on 65500
  (`curl -k https://127.0.0.1:65500/`) and that port isn't blocked by the nftables firewall
  (`nft list ruleset` to inspect it; port 65500 should be reachable via the `user_accept`/base
  `input` chain rules — see [TECHNICAL.md §7](TECHNICAL.md#7-firewall-nftablesconf-nftables--migrated-off-shorewall)).
- **Re-running the installer does nothing**: you likely have `REINSTALL=no` and are already on the
  current version — set `REINSTALL=yes` to force it.
- **Wrong network interface detected**: set `INTERFACE`/`INTERFACE6` explicitly and re-run.

## 10. Uninstalling

There is no automated uninstaller. Removing the `omr-server` package removes the files this repo
installs, but tunnel packages, the kernel, and the nftables configuration under `/etc/nftables.conf`
/ `/etc/nftables/` are left in place — plan a full VM/VPS teardown if you want a clean slate.
