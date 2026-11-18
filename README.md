# confdrift

`diff` for Cisco configs that understands sections, ignores the junk, and tells you which changes can hurt.

```
$ confdrift examples/core-sw01.before.cfg examples/core-sw01.after.cfg --risk-only
confdrift: core-sw01
  4 added, 2 removed, 2 modified, 1 reordered across 8 section(s)

RISK
  HIGH   global: local user with reversible password
         + username tempadmin privilege 15 password 0 <redacted>
  HIGH   interface GigabitEthernet1/0/24: ACL removed from interface - traffic is no longer filtered
         - ip access-group CORE-IN in
  HIGH   interface GigabitEthernet1/0/1: trunk allowed list changed (pruned 30,99, added 40)
         - switchport trunk allowed vlan 10,20,30,99
         + switchport trunk allowed vlan 10,20,40
  HIGH   ip access-list extended CORE-IN: entries re-ordered; first match wins, so behaviour changed
  HIGH   global: default SNMP community
         + snmp-server community <redacted> RW
  HIGH   line vty 0 4: telnet allowed on VTY
         - transport input ssh
         + transport input ssh telnet
  MEDIUM global: password encryption turned off
         - service password-encryption
```

## The problem

You take a backup before a change window and another one after. Then someone asks "what changed on core-sw01 last Friday?" and you run `diff before.cfg after.cfg`. You get:

- the `! Last configuration change at ...` line, every time
- `Current configuration : 6214 bytes`, every time
- a whole interface block shown as deleted and re-added because it moved 20 lines down
- no hint that the one line that actually matters is `switchport trunk allowed vlan 10,20,40`, which just pruned the MGMT VLAN off the trunk to the access switch.

`show archive config differences` on the box is better, but it only works on that box and it doesn't rank anything.

## What confdrift does differently

**Diffs the tree, not the text.** IOS config is a tree in indentation. `interface Gi1/0/1 > switchport mode trunk` either exists in both files or it doesn't. Moving blocks around, or a different `show run` order between IOS versions, gives zero noise.

**Knows where order matters.** Under `interface` order doesn't matter. Under `ip access-list`, `route-map`, `policy-map` it does, because first match wins. Swapping two ACL lines shows up as a high-risk *reorder*. If the lines have sequence numbers it orders by those, the same way the box does.

**Knows "replace" from "remove".** Commands that can only exist once per section (`description`, `ip address`, `switchport trunk allowed vlan`, `transport input`, ...) get paired into a single *modify*. That matters for trunks: removing the allowed list means *all* VLANs, replacing it means some get pruned. For trunks it works out which ones.

**Ranks changes.** About 30 rules in [`risk.py`](confdrift/risk.py), things like ACL pulled off an interface, BGP neighbour or its route-map changed, default route touched, telnet enabled on VTY, `public`/RW SNMP community, `enable password` instead of `enable secret`, AAA removed, bpduguard removed. Each one is a single line of data, so adding your own is easy.

**Redacts secrets by default.** Passwords, secrets, keys and SNMP communities show as `<redacted>`, so you can paste the output in a ticket or a WhatsApp group without leaking anything. `--show-secrets` turns that off.

## Install

```
pip install git+https://github.com/GreatsLab/confdrift
```

Python 3.10+, standard library only.

## Usage

```
confdrift OLD NEW                 # full report
confdrift OLD NEW --risk-only     # just the ranked findings
confdrift OLD NEW --json          # for scripts / dashboards
confdrift OLD NEW --fail-on high  # exit 3 if anything high-risk changed
```

### In CI on a config backup repo

If you keep backups in git (Oxidized, RANCID, or a cron job with `scp`), this fails the pipeline when a commit brings in a high-risk change:

```yaml
- run: pip install git+https://github.com/GreatsLab/confdrift
- run: |
    for f in $(git diff --name-only HEAD~1 -- '*.cfg'); do
      git show HEAD~1:$f > /tmp/old.cfg
      confdrift /tmp/old.cfg $f --risk-only --fail-on high
    done
```

## Limitations

- IOS / IOS-XE style configs. NX-OS mostly works since it's the same indentation idea. Junos `set` format doesn't.
- `banner` blocks with odd delimiters may come out as separate lines.
- The risk list is opinionated. PRs welcome.

## License

MIT
