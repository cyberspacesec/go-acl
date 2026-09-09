# acl-skills

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.18+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License" />
  <img src="https://img.shields.io/codecov/c/github/cyberspacesec/acl-skills?style=flat-square&logo=codecov&logoColor=white" alt="Coverage" />
  <img src="https://img.shields.io/github/v/release/cyberspacesec/acl-skills?style=flat-square&logo=github&label=release" alt="Release" />
</p>

<p align="center">
  <b>Access Control Library for AI Agents — Block SSRF, Control Outbound Domains & IPs</b>
</p>

---

AI agents make HTTP calls as part of their tool use. Without guardrails, they can be tricked into accessing internal services (SSRF), leaking data to unintended destinations, or hitting cloud metadata endpoints. **acl-skills** gives you a clean Go API to enforce domain and IP allow/deny lists before any outbound request leaves your agent.

```go
// One call to protect your agent from SSRF and unintended outbound access
manager.SetIPACLWithDefaults(nil, types.Blacklist, []ip.PredefinedSet{
    ip.PrivateNetworks,   // 10.x, 192.168.x, 172.16.x
    ip.LoopbackNetworks,  // 127.x, ::1
    ip.CloudMetadata,     // 169.254.169.254, fd00:ec2::254
    ip.DockerNetworks,    // 172.17.x
}, false)

if perm, _ := manager.CheckIP(resolvedIP); perm == types.Denied {
    return errors.New("access denied: internal address")
}
```

## Why agents need ACL

| Risk | Without acl-skills | With acl-skills |
|------|-------------------|----------------|
| SSRF via user-supplied URL | Agent fetches internal services | Blocked before request leaves |
| Prompt injection → data exfil | Agent POSTs to attacker server | Domain blocklist catches it |
| Cloud credential theft | Agent hits `169.254.169.254` | CloudMetadata preset blocks it |
| Unauthorized tool use | No guardrails on what agent calls | Per-kind ACL with audit trail |

## Installation

```bash
go get github.com/cyberspacesec/acl-skills
```

Requires Go 1.18+, zero external dependencies.

## Quick Start

### Scenario 1 — Protect a web-fetching tool

```go
import (
    "github.com/cyberspacesec/acl-skills/pkg/acl"
    "github.com/cyberspacesec/acl-skills/pkg/ip"
    "github.com/cyberspacesec/acl-skills/pkg/types"
)

manager := acl.NewManager()

// Block all addresses an agent should never reach
manager.SetIPACLWithDefaults(nil, types.Blacklist, []ip.PredefinedSet{
    ip.PrivateNetworks,
    ip.LoopbackNetworks,
    ip.CloudMetadata,
    ip.LinkLocalNetworks,
    ip.DockerNetworks,
}, false)

// Before your agent's HTTP dial:
func agentDial(network, addr string) (net.Conn, error) {
    host, _, _ := net.SplitHostPort(addr)
    if perm, _ := manager.CheckIP(host); perm == types.Denied {
        return nil, fmt.Errorf("acl: blocked %s", host)
    }
    return net.Dial(network, addr)
}
```

### Scenario 2 — Allowlist which domains an agent may call

```go
manager := acl.NewManager()

// Only allow calls to your own APIs and approved third-party services
manager.SetDomainACL([]string{
    "api.openai.com",
    "api.anthropic.com",
    "your-backend.internal",
}, types.Whitelist, true) // true = include subdomains

if perm, _ := manager.CheckDomain(targetHost); perm == types.Denied {
    return fmt.Errorf("acl: domain %s not in allowlist", targetHost)
}
```

### Scenario 3 — JSON policy file (great for agent config)

Define rules in a file your orchestration system can inject at startup:

```json
{
  "ip": {
    "listType": "blacklist",
    "predefinedSets": ["private_networks", "loopback", "cloud_metadata", "docker_networks"],
    "allowPredefined": false
  },
  "domain": {
    "domains": ["evil-exfil.com", "attacker.io"],
    "listType": "blacklist",
    "includeSubdomains": true,
    "predefinedSets": ["shorteners", "disposable_email"],
    "allowPredefined": false
  }
}
```

```go
pol, _ := config.LoadPolicyFromFile("./agent-policy.json")
manager := acl.NewManager()
manager.ApplyPolicy(pol)
```

### Scenario 4 — HTTP middleware for agent services

If your agent exposes an HTTP service or proxy, add ACL as middleware:

```go
handler := middleware.New(manager, middleware.Options{
    CheckClientIP: true,  // block inbound connections from bad IPs
    CheckHost:     true,  // block requests to blocked domains
    // TrustProxy: false by default — prevents X-Forwarded-For spoofing
})(mux)
http.ListenAndServe(":8080", handler)
```

Any denied request returns 403. `TrustProxy` is `false` by default to prevent header-spoofing bypasses.

## Core API

```go
manager := acl.NewManager()

// Domain ACL
manager.SetDomainACL(domains []string, list types.ListType, includeSubdomains bool)
manager.SetDomainACLWithDefaults(domains, list, includeSubdomains, predefined, allowPredefined)
manager.AddDomain(domains ...string)
manager.RemoveDomain(domains ...string)
perm, err := manager.CheckDomain(domain string)

// IP ACL
manager.SetIPACL(ranges []string, list types.ListType)
manager.SetIPACLWithDefaults(ranges, list, predefined, allowPredefined)
manager.AddIP(ips ...string)
manager.RemoveIP(ips ...string)
perm, err  := manager.CheckIP(ip string)
cidr, err  := manager.LookupIP(ip string)   // longest-prefix reverse lookup

// Unified policy
manager.ApplyPolicy(pol *config.Policy)

// Custom ACL kinds (extend for tokens, user IDs, API keys, …)
manager.RegisterACL("api-key", myKeyACL)
perm, err := manager.CheckKind("api-key", value)
```

## Predefined IP Sets

| Constant | Covers | Agent use case |
|----------|--------|---------------|
| `ip.PrivateNetworks` | RFC 1918 (10.x, 172.16.x, 192.168.x) | Block intranet SSRF |
| `ip.LoopbackNetworks` | 127.x, ::1 | Block localhost access |
| `ip.CloudMetadata` | 169.254.169.254, fd00:ec2::254 | Protect cloud credentials |
| `ip.LinkLocalNetworks` | 169.254.x, fe80::/10 | Block link-local |
| `ip.DockerNetworks` | 172.17.x | Block container network |
| `ip.PublicDNS` | 8.8.8.8, 1.1.1.1, … | DNS server allowlist |

## Predefined Domain Sets

| Constant | Covers | Agent use case |
|----------|--------|---------------|
| `domain.Shorteners` | bit.ly, tinyurl, … | Block hidden redirect targets |
| `domain.DisposableEmail` | mailinator, guerrilla, … | Block throwaway addresses |
| `domain.PublicFileSharing` | pastebin, mega, … | Block data exfiltration |
| `domain.CodeHosting` | github, gitlab, … | Control source code access |
| `domain.SocialMedia` | twitter, reddit, … | Enterprise policy enforcement |
| `domain.TorExitNodes` | Tor-related domains | Block anonymous traffic |
| `domain.TrustedCDN` | cloudflare, fastly, … | CDN allowlist |
| `domain.AllMaliciousDomains` | All high-risk sets combined | Maximum lockdown |

## Domain Pattern Matching

Beyond exact matches, the domain ACL supports wildcards and regex:

```go
manager.SetDomainACL([]string{
    "*.evil.com",          // subdomains only (evil.com itself passes)
    "*evil.com",           // evil.com and all subdomains
    "api.*",               // any domain starting with api.
    `/^internal-\d+\.corp$/`, // RE2 regex (no backtracking, ReDoS-safe)
}, types.Blacklist, false)
```

## IP Range Support

```go
// CIDR
manager.SetIPACL([]string{"10.0.0.0/8", "2001:db8::/32"}, types.Blacklist)

// Closed interval — auto-merged into minimal CIDR set
manager.SetIPACL([]string{"192.168.1.10-192.168.1.20"}, types.Blacklist)
```

## Extensibility

Register custom ACL kinds for any string-valued resource (API keys, user IDs, OAuth scopes):

```go
// MutableACL interface: Check / GetListType / Add / Remove / GetRules
manager.RegisterACL("oauth-scope", myScopeACL)
perm, _ := manager.CheckKind("oauth-scope", "write:data")
manager.AddRule("oauth-scope", "read:public")
```

Built-in `KindDomain` / `KindIP` are pre-registered; all legacy `SetDomainACL`/`CheckIP` calls remain compatible.

## Performance

Benchmarked with `go test -bench=. -benchmem ./...`:

| Operation | Scale | Latency | Allocs |
|-----------|-------|---------|--------|
| `IPACL.Check` | 10 000 rules | ~75 ns/op | 0 |
| `IPACL.Check` (concurrent) | 10 000 rules | ~45 ns/op | 0 |
| `DomainACL.Check` (exact) | 10 000 rules | ~70 ns/op | 0 |
| `Manager.CheckIP` | 10 000 rules | ~80 ns/op | 0 |

IP matching uses a bitwise prefix trie (O(32) for IPv4, O(128) for IPv6) — lookup time is constant regardless of rule count. Check paths are zero-allocation.

## Examples

| Example | Description |
|---------|-------------|
| [01_domain_acl](examples/01_domain_acl/) | Basic domain allowlist/blocklist |
| [02_ip_acl](examples/02_ip_acl/) | IP blocklist with CIDR |
| [04_predefined_sets](examples/04_predefined_sets/) | SSRF protection with presets |
| [05_acl_manager](examples/05_acl_manager/) | Combined domain + IP rules |
| [06_complete_example](examples/06_complete_example/) | Full web application guard |
| [07_custom_acl](examples/07_custom_acl/) | Custom ACL kind registration |
| [08_http_middleware](examples/08_http_middleware/) | JSON policy + middleware |
| [09_domain_predefined_sets](examples/09_domain_predefined_sets/) | Domain preset collections |
| [10_subdomain_acl](examples/10_subdomain_acl/) | Subdomain wildcard patterns |
| [11_ipv6_subnet_acl](examples/11_ipv6_subnet_acl/) | IPv6 subnet + reverse lookup |
| [12_domain_pattern_acl](examples/12_domain_pattern_acl/) | Prefix / suffix / regex patterns |
| [13_ip_range_acl](examples/13_ip_range_acl/) | IP interval ranges |

## API Stability

From `v1.0.0`, the following are guaranteed stable across minor versions:

- `types`: `ACL`, `ListTypeACL`, `MutableACL`, `ListType`, `Permission`
- `domain.DomainACL`, `ip.IPACL`: `Check` / `Add` / `Remove` / `GetRules` / `GetListType`
- `acl.Manager`: all `Set*` / `Check*` / `Add*` / `Remove*` / `Get*` / `LookupIP` methods
- `config.Policy` struct and JSON field names
- `middleware.New` and `Options` fields

Experimental (may change in minor versions): `Manager.RegisterACL` / `UnregisterACL`, `SetDomainACLStrict`.

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
