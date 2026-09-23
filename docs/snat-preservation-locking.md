# Exact SNAT preservation checkpoint

Snapshot and restore now require a verified `iptables --version` legacy backend.
They hold the conventional `XTABLES_LOCKFILE` (default `/run/xtables.lock`) with
an exclusive flock through the complete table operation. Restore keeps that lock
through all identity checks, positional deletions and final readback. Child
iptables processes receive a separate lock file in a private temporary directory,
avoiding a deadlock on the parent's lock. The conventional lock is never removed.
Acquisition is bounded to five seconds; symlink and nonregular lock files fail.

This protects against writers using the same conventional legacy lock in the
same mount/network context. Writers that deliberately bypass or replace that lock
remain outside the guarantee. The lock is released between the pre-apply snapshot
and global SDN apply: holding it across Proxmox's own firewall commands would
deadlock. Unexpected drift still fails closed, possibly after SDN apply completed.

`iptables-nft` and unrecognized backends are refused before the snapshot/table
read, hence before the calling composite's first SDN write. Netfilter documents
that `--wait` is a no-op on nft; an outer legacy flock cannot safely protect a
numbered nft deletion. A separate handle-based nft implementation is still needed.
The existing list and exact-source `reconcile CIDR 0|1` commands are unchanged.
The lab's actual iptables backend has not been verified in this checkpoint.

Tests use a private fake table and independent processes with real flock. The
writer inserts a rule after the helper's last check: the old implementation
deleted the wrong position; the transaction defers that writer until restoration
finishes. Four new regressions failed before the fix; all 34 focused helper and
real-Ansible checks pass afterward. No host firewall command, full repository
suite, or live activation was performed. The environment's pre-existing pytest
asyncio default-loop deprecation warning is unrelated to these synchronous tests.

`snapshot-reviewed` now accepts a JSON preservation policy before reading the
table: `excluded_sources` is a unique canonical IPv4 CIDR list (maximum 64), and
`allow_new_rules` is a boolean. It records that exact policy in `reviewed_policy`;
restore refuses a different policy. This is an accidental-scope-change guard in
trusted automation, not a cryptographic authorization boundary.

Listed source NAT rules may be removed/reordered/replaced by pending apply.
Non-NAT rules and untouched source rules retain their relative order, arguments
and original multiplicities. Only exact appended duplicate identities are
deleted. `allow_new_rules` permits appended rules for new source CIDRs; new
shapes for existing untouched sources fail before any cleanup. The strict 0/1
reconcile primitive remains separate and unchanged.

The continuation passed 55 focused controller tests, including four real-Ansible
cases. Invalid review input stops before the simulated apply; listed changes,
untouched-source drift, non-NAT protection and stale policy all have regressions.

The paired playbooks worktree remains incomplete: a global apply needs snapshots,
target reconciliation and preservation covering every affected cluster node.
No nft implementation, multi-node coverage or live acceptance is claimed.
Do not activate the paired preservation release until those gaps are handled.

References: [iptables locking and XTABLES_LOCKFILE](https://man7.org/linux/man-pages/man8/iptables.8.html),
[Netfilter's nft backend semantics](https://man7.org/linux/man-pages/man8/xtables-nft.8.html),
and [Proxmox cluster-wide SDN configuration](https://github.com/proxmox/pve-docs/blob/master/pvesdn.adoc).
