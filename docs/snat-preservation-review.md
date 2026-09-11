# Incomplete SNAT preservation checkpoint

Do not activate this branch. It is an isolated continuation from controller
`99fd63c`, intended to pair with the playbooks preservation worktree.

The new snapshot/restore operation preserves exact existing rule identities,
counts and order, removes only appended duplicate identities, excludes explicitly
selected source CIDRs, and keeps the existing desired-state primitive at 0/1.
Snapshots are hidden from Ansible output; failures use a fixed diagnostic.

Verified locally: 26 helper/parser tests and two actual Ansible snapshot/restore
cases pass, including concurrent-change rejection and sanitized diagnostics.
No live networking was changed. Full repository checks have not run on this
checkpoint.

The unresolved blocker is the numbered-delete race: a complete fresh table check
runs before every deletion, but an independent writer could change positions
between that check and the delete. `iptables -w` locks individual commands.
Consider holding the conventional xtables lock across the restore operation,
using a private child-command lock file to avoid self-deadlock, and add contention
and unexpected-writer tests before review. Native nft writers still require
coordination. Do not claim atomic preservation from the current implementation.

Standalone apply retains new NAT identities, but removes/reorders of original
rules cause preservation to refuse further deletion after apply. This partial
outcome needs a documented operator workflow. Coverage currently concerns one SSH
target node; Proxmox SDN apply is cluster-wide.
