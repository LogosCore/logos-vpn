# logos-vpn

Logos's VPN client: routes an operator's machine into a tunnel's networks
(docs: [VPN Front](https://logoscore.github.io/logos-docs/contracts/vpn-front/)).
While it runs, every tool on the machine reaches the tunnel's routes
through its minion, nmap's SYN scan and `ping` among them; Ctrl-C
disconnects it.

```sh
sudo logos-vpn https://logos.example.com lgv_…
```

The command, with a key of the operator's, comes from the tunnel task's
**VPN** tab (**Connect a machine**). On Windows the same runs in an
elevated PowerShell (`.\logos-vpn.exe …`). The key may come from
`LOGOS_VPN_KEY` instead of the command line.

| Flag | |
|---|---|
| `-interface` | the interface's name: `logos0` (Linux), any free `utun` (macOS), `logos-vpn` (Windows) |
| `-mtu` | the interface's MTU, 1500 |
| `-version` | the release |

## What it does

- Connects to core's own address (`GET /api/v1/vpn`, a WebSocket), the key
  its bearer, and gets the tunnel's routes.
- Adds an interface (wireguard-go's `tun`: a TUN on Linux, a utun on macOS,
  a Wintun adapter on Windows) with addresses of its own (`198.18.255.1`,
  `fdc0:6c6f:676f:7300::1`), and a route through it for each of the
  tunnel's networks, but those the machine's interfaces are on and the one
  that holds core's address.
- Ends each TCP connection in a user-space TCP/IP stack (gVisor's): the SYN
  is answered once the minion's host answered (open: the handshake;
  refused: a reset; unreachable, denied: an ICMP error; timed out: nothing).
  Each UDP source is an association; pings go as datagrams of their own.
  Nothing else is answered: a stray packet gets no reset, and nothing comes
  in that the machine did not start.
- Keeps its interface and routes while its link is down, and connects again
  for 2 minutes, losing nothing: each side sends again from the other's
  last ack.

## Building

```sh
make dist   # dist/logos-vpn-{linux,darwin,windows}-{amd64,arm64}[.exe]
make test
make lint
```

Windows builds carry Wintun's signed `wintun.dll` (from wintun.net,
checked against its published SHA-256, unmodified as its license lets it
go with an application), written beside the executable as it starts.

Core serves each release's binaries from `VPN_CLIENT_DIR`; the link's
version (`protocol.VPNLink`) is what core and the client must share.
