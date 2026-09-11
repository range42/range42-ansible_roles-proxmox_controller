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

The paired playbooks worktree remains incomplete: legitimate pending removals or
reordering need an explicit reviewed scope, and a global apply needs snapshots,
target reconciliation and preservation covering every affected cluster node.
Do not activate the paired preservation release until those gaps are handled.

References: [iptables locking and XTABLES_LOCKFILE](https://man7.org/linux/man-pages/man8/iptables.8.html),
[Netfilter's nft backend semantics](https://man7.org/linux/man-pages/man8/xtables-nft.8.html),
and [Proxmox cluster-wide SDN configuration](https://github.com/proxmox/pve-docs/blob/master/pvesdn.adoc).
