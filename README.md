# LAN Service Gateway

An OpenWrt APK that makes selected LocalSend devices behind a NAT router discoverable from its upstream LAN. It also supports static port forwarding to one Sunshine host. File transfers and game streams stay end to end; the gateway forwards packets without terminating application TLS.

## What it does

```text
Upstream LAN client
        │ discovers the router's upstream IP and proxy port
        ▼
OpenWrt router (multicast discovery + nftables DNAT)
        │ forwards to an explicitly configured device
        ▼
Downstream LocalSend or Sunshine host
```

- **LocalSend:** Reannounces allowed downstream devices on the upstream LAN. Each device gets a distinct TCP proxy port. At startup, the gateway reads the device's HTTPS `/api/localsend/v2/info`, checks that its reported fingerprint matches its TLS certificate, and announces it. An upstream LocalSend announcement triggers a rate-limited replay of cached downstream announcements. Upstream clients register through the proxy port; the downstream device learns those clients from their registration requests.
- **Sunshine:** Optionally forwards the configured TCP and UDP ports for one downstream host. Add the router's upstream IP manually in Moonlight.
- **OpenWrt integration:** Uses UCI, procd, an interface hotplug hook, and dedicated firewall4/nftables chains. It updates only its own live chains; it does not reload the whole firewall.

The package is disabled on installation. It does not create shadow IPs, relay generic multicast or SSDP, publish mDNS records, or provide Moonlight auto-discovery. It currently supports IPv4.

## Requirements

- OpenWrt 25.12 with firewall4 and the `apk` package manager.
- Separate upstream and downstream IPv4 networks with the downstream routed/NATed through OpenWrt.
- A fixed DHCP lease or static IP for each configured downstream device.
- A trusted upstream LAN: configured proxy ports are reachable from that LAN.

The prebuilt APK on the [v0.1.0-r3 Release](https://github.com/brill594/shadow/releases/tag/v0.1.0-r3) targets **OpenWrt 25.12.5, `mediatek/filogic`, `aarch64_cortex-a53`**. Build a new package with a matching SDK for a different target.

## Install

Download the APK and `SHA256SUMS` from the [Release](https://github.com/brill594/shadow/releases/tag/v0.1.0-r3), verify the checksum, copy the APK to the router, then install it:

```sh
apk --allow-untrusted add /tmp/lan-service-gateway-0.1.0-r3.apk
```

The APK is unsigned, so `--allow-untrusted` is required for this local build. Installation alone creates no port forwards.

## Configure LocalSend

Edit `/etc/config/lan-service-gateway`. Keep the logical network names aligned with your OpenWrt `lan` and upstream interface, often `wwan`:

```text
config service 'main'
    option enabled '0'
    option lan_network 'lan'
    option wan_network 'wwan'

config localsend
    option ip '192.168.10.50'
    option port '53317'
    option proxy_port '55001'
    option fingerprint '-'
```

`ip` and `port` identify the real downstream LocalSend server. `proxy_port` is advertised on the router's upstream IP and must be unique among configured services. `fingerprint` may be set to the expected certificate SHA-256 fingerprint; `-` accepts the certificate currently served by that fixed IP, while still checking that `/info` reports the same identity. Add another `config localsend` section for each additional downstream device.

Enable the gateway after reviewing the mappings:

```sh
uci set lan-service-gateway.main.enabled='1'
uci commit lan-service-gateway
/etc/init.d/lan-service-gateway restart
/etc/init.d/lan-service-gateway status
```

The service validates the generated firewall4 rules before inserting its live nftables rules. If the upstream interface address changes, the hotplug hook restarts the service and regenerates the mapping.

## Configure Sunshine (optional)

Add one `config sunshine` section with the host's actual service ports; the [sample UCI file](package/files/lan-service-gateway.config) shows the syntax. Confirm the port list against your Sunshine configuration and [Sunshine's port documentation](https://docs.lizardbyte.dev/projects/sunshine/v0.23.0/about/advanced_usage.html). Moonlight clients must add the router's upstream IP manually. Sunshine streaming and mDNS auto-discovery are separate from LocalSend discovery; this package does not implement mDNS publication.

## Build an APK

On a Linux x86_64 build host with Docker, download and extract the OpenWrt SDK matching your firmware release and target. Then run:

```sh
bash scripts/build-apk.sh /path/to/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64
```

The script tests the Go code in `golang:1.26.7`, cross-compiles a static arm64 binary, builds the package with the SDK, and copies the APK to the local `dist/` directory. APKs and checksums are distributed as GitHub Release assets rather than committed to the source repository.

## Verify and troubleshoot

```sh
/etc/init.d/lan-service-gateway status
nft list chain inet fw4 lsg_dstnat
nft list chain inet fw4 lsg_forward
logread | grep lan-service-gateway
```

Test discovery and an actual small file transfer in **both directions**. If a peer does not appear, check its current IP and LocalSend port, its DHCP reservation, the router's upstream address, and whether multicast reaches the router's LAN interface. Seeing an announcement alone does not prove that HTTPS registration or file transfer succeeded.

To disable the gateway and remove its live mappings:

```sh
uci set lan-service-gateway.main.enabled='0'
uci commit lan-service-gateway
/etc/init.d/lan-service-gateway stop
```

## Validation scope

Release `0.1.0-r3` was built with the OpenWrt 25.12.5 `mediatek/filogic` SDK. Its package transaction and generated nftables syntax were checked on the target router; a real two-way LocalSend file transfer was confirmed. Sunshine forwarding is implemented but has not been validated with a live Sunshine host.

Licensed under [MIT](LICENSE).
