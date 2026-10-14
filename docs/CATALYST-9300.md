# Running a PTP Monitor node on a Cisco Catalyst 9300 / 9300X

This guide runs the **remote node** (no web UI) as a Docker container on the switch, using
IOS XE **Application Hosting**. The node watches PTP on the switch's VLANs and pushes what it
sees to a **collector** over HTTPS. The collector is where you look at the data and, if you
want, tell the node to join a PTP domain (see the main [README](../README.md#collector-and-nodes)).

```
 PTP devices ── front-panel ports ── Catalyst 9300/9300X ── management / uplink ── Collector
                                      │  AppGigabitEthernet (internal)               (HTTPS 8443)
                                      └─ container "ptp_node"
                                          eth0 = management  → pushes to the collector
                                          eth1 = PTP VLAN    → captures / joins the PTP domain
```

> **Status.** The image and the settings below follow Cisco's published Application Hosting
> documentation. They have **not been tested on a physical switch** by the author of this
> repository. Items that depend on your IOS XE release are marked *check*. Please validate in a
> lab first, and report what differs.

## 1. What you need

| | |
|---|---|
| Switch | Catalyst **9300** (IOS XE 16.12.1 or later) or **9300X** (IOS XE 17.5.1 or later). 9200 is not supported. |
| License | Cisco Smart Licensing; DNA Advantage is required for app hosting. |
| Storage | An **SSD (or USB 3.0 drive) in the back-panel slot**. Apps cannot run from internal flash on the 9300. Enabling `iox` reserves about 4 GB. |
| Architecture | x86_64 (the image is built for `linux/amd64`). |
| Network | The container needs an IP address and a route to the collector. The 9300X has two 10G AppGigabitEthernet ports. |
| Collector | Running and reachable from the switch, with a node and token created (section 3). |
| Build host | Docker with buildx, any OS. |

Sources: [Cisco: Understand App Hosting on Catalyst 9000](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9500-series-switches/222780-understand-app-hosting-on-catalyst-9000.html).

## 2. Build the image

```bash
iox/build.sh 1.0          # -> ptp-node-1.0.tar (docker save of a linux/amd64 image)
```

That runs `docker buildx build --platform linux/amd64 -f Dockerfile.iox` and `docker save`.
The tar of every build on GitHub is also attached to the *Container image* workflow run
(artifact `ptp-node-iox`). The image is about 200 MB; at runtime it needs roughly
256 MB RAM and 100 MB disk.

Copy it to the switch SSD (use `usbflash1:` or `ssd1:`, whichever `dir ?` shows):

```
copy scp://user@buildhost/ptp-node-1.0.tar usbflash1:ptp-node-1.0.tar
verify /sha256 usbflash1:ptp-node-1.0.tar          ! compare with the checksum printed by build.sh
```

## 3. Prepare the collector

On the collector (see the README), create the node and keep the token and the fingerprint:

```bash
python ptp_monitor.py --mode collector --add-node cat9300-idf1
```

or use the Admin page. A self-signed collector prints a **SHA-256 fingerprint**; the node pins
it, so no CA is needed on the switch. The switch must reach the collector's port 8443 (the node
only connects out; the collector never connects to the switch).

## 4. Configure the switch

### 4.1 Enable IOx

```
configure terminal
 iox
end
show iox-service           ! CAF, IOxman, Docker... should all show Running
```

### 4.2 Networking

The container gets two interfaces; the numbers are the *guest-interface* numbers and become
`eth0` / `eth1`.

* **eth0 = management** (Gi0/0, in `Mgmt-vrf`): carries the HTTPS push to the collector.
* **eth1 = PTP VLAN** through the internal AppGigabitEthernet port: where PTP is captured.
  It needs an IPv4 address on the PTP VLAN so the node can send IGMP joins and Delay_Req
  when the collector tells it to join a domain.

```
vlan 100
 name PTP
interface AppGigabitEthernet1/0/1
 switchport mode trunk
 switchport trunk allowed vlan 100
!
app-hosting appid ptp_node
 app-vnic management guest-interface 0
  guest-ipaddress 10.1.1.50 netmask 255.255.255.0
 app-vnic AppGigabitEthernet trunk
  vlan 100 guest-interface 1
   guest-ipaddress 10.100.0.50 netmask 255.255.255.0
 app-default-gateway 10.1.1.1 guest-interface 0
 name-server0 10.1.1.2
 app-resource profile custom
  cpu 1000
  memory 256
  persist-disk 100
  vcpu 1
 app-resource docker
  run-opts 1 "-e PTP_COLLECTOR_URL=https://collector.example.com:8443"
  run-opts 2 "-e PTP_NODE_TOKEN=ptpn_PASTE-TOKEN-HERE"
  run-opts 3 "-e PTP_COLLECTOR_FINGERPRINT=AA:BB:CC:...:ZZ"
  run-opts 4 "-e PTP_INTERFACES=eth1"
  run-opts 5 "--cap-add=NET_ADMIN --cap-add=NET_RAW"
end
```

*Check:* the exact sub-commands (`app-vnic ... vlan N guest-interface`, `persist-disk`) differ a
little between releases; use `?` in config mode. Every port that has PTP devices on VLAN 100
must also be configured on the switch as usual. On a 9300X use `AppGigabitEthernet1/0/1` or
`1/0/2`. Use an IP in the collector's reachable range; with an IP address instead of a name
you do not need `name-server0` (the pinned fingerprint does not depend on the name).

Alternative with **one** interface: put everything on a VLAN that can reach the collector
(`vlan 100 guest-interface 0`, no management vNIC), set `PTP_INTERFACES=eth0` and
`app-default-gateway` on guest-interface 0.

**The token is in the switch configuration.** Anyone who can read `show running-config` can
read it. Keep config access restricted, and if it leaks, get a new token on the collector's Admin
page (*New token*) and update `run-opts 2`. The node's rights are limited to pushing its own data.

### 4.3 Install, activate, start

```
app-hosting install appid ptp_node package usbflash1:ptp-node-1.0.tar
show app-hosting list                  ! DEPLOYED
app-hosting activate appid ptp_node
app-hosting start appid ptp_node
show app-hosting list                  ! RUNNING
```

Configuring `start` inside `app-hosting appid ptp_node` makes it start after a reload. To
change run-opts or networking later: `app-hosting stop`, `deactivate`, edit, `activate`, `start`.

## 5. Check that it works

1. On the switch: `show app-hosting detail appid ptp_node` (state RUNNING, interfaces up),
   then `app-hosting connect appid ptp_node session` for a shell, and
   `python /app/healthcheck.py` (no output = the collector accepted a push in the last 30 s).
2. On the collector: the node `cat9300-idf1` shows **online** within a few seconds.
3. Logs: `app-hosting move appid ptp_node log to bootflash:` and read the file; a bad token,
   fingerprint or route shows up there as a push error.

## 6. Getting PTP traffic to the container

PTP uses multicast (224.0.1.129, 224.0.0.107). A container port only receives what the switch
forwards to it:

* **Join from the collector (works with the setup above).** On the collector, open the node and
  click *Join domain*. The node sends IGMP joins from eth1, so VLAN 100's IGMP snooping
  forwards the PTP groups to the container. It then acts as a PTP slave and the collector shows
  the master, offset and delay as seen from the switch.
* **Passive capture.** To see the PTP traffic of other ports without joining, mirror them to the
  application port. Cisco's third-party guides use `mirroring` on the guest interface
  (`guest-interface 1` + `mirroring`) or a SPAN session whose destination is the
  AppGigabitEthernet port. *Check* the support for your IOS XE release in Cisco's SPAN and
  Application Hosting documents; this is not verified here.
* **Switch as a PTP clock.** The 9300 handling PTP itself (boundary / transparent clock) changes
  what the node sees; capture one of the switch's own ports in a lab before relying on it.

## 7. Upgrading, rotating, removing

```
app-hosting stop appid ptp_node
app-hosting deactivate appid ptp_node
app-hosting uninstall appid ptp_node
app-hosting install appid ptp_node package usbflash1:ptp-node-1.1.tar
app-hosting activate appid ptp_node
app-hosting start appid ptp_node
```

The configuration under `app-hosting appid ptp_node` stays. To rotate the token use *New token*
token* on the collector, then change `run-opts 2` (stop/deactivate first).

## 8. Optional: IOx package (ioxclient)

From IOS XE 16.12 the `docker save` tar installs as it is. If your process requires an IOx
package, `iox/package.yaml` is a descriptor for
`ioxclient docker package --skip-envelope-pkg ptp-node:1.0 iox/` (untested).

## 9. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `install` fails | Tar not on the SSD, `iox` not running, no free space, or the file is not a `docker save` archive of a linux/amd64 image. |
| `activate` fails | Resource profile too large for the platform, or a run-opts option that IOS XE blocks (`--privileged`, `--name`, `--ip`... are not allowed). |
| Node never shows online | No route/DNS from eth0 to the collector (check the gateway and the Mgmt-vrf), wrong URL, firewall on 8443. The log says which. |
| "fingerprint does not match" | The collector certificate changed. Copy the new fingerprint into `run-opts 3`. |
| 401 / "token" error | Wrong or rotated token. |
| Online, but no PTP data | eth1 sees no multicast: VLAN not allowed on the AppGigabitEthernet trunk, no IGMP join (use *Join domain*), or no mirroring configured (section 6). `PTP_INTERFACES` must name the PTP interface (`eth1`). |
| "Join domain" fails | eth1 has no IPv4 address, or the collector's node has remote control disabled (`PTP_NO_REMOTE_CONTROL`). |
| Healthcheck "no push accepted" | Same as *never shows online*. |

## 10. Not verified

* Running on real Catalyst 9300 / 9300X hardware; CLI sub-command names per IOS XE release.
* Whether your release delivers mirrored traffic to a guest interface (section 6).
* `--cap-add` acceptance and promiscuous mode on the app port.

What *is* tested in CI: the image builds for linux/amd64, starts in node mode, and pushes to a
collector container over HTTPS using a pinned certificate fingerprint.
