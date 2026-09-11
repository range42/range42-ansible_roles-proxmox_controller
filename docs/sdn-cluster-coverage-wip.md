# Incomplete cluster coverage checkpoint — do not activate

This continuation starts at controller `e7a7332` in
`/tmp/r42-sdn-controller-preservation-next-wave`. Paired playbooks remain
`fb536e79ea969de6378e3cd272f75b878b0a03b3` in
`/tmp/r42-sdn-preservation-next-wave`; their production source has not been
updated for this continuation. The user requested a checkpoint before further
implementation. No live SSH, firewall, SDN or release mutation was performed.

## Implemented and tested primitives

- `files/snat_cluster.py`: bounded cluster planning from authenticated
  `/cluster/status`, complete unique `sdn_snat_node_hosts` mapping into
  `proxmox_cli`, online/quorum checks, legitimate single-node default, and
  simple-zone membership. Every cluster node is covered; desired source
  reconciliation applies only to zone members. Ambiguous CIDRs shared with
  another declared VNet are refused.
- Snapshot collection checks each returned actual hostname and reviewed policy
  against the mapped node. Node-local observation timestamps support task
  history queries without assuming synchronized controller clocks.
- Reload baseline/completion parsing rejects active pre-existing reloads,
  malformed or wrong-node tasks, ambiguous concurrent new workers and failed
  workers. Prior successful tasks are insufficient completion evidence.
- `snat_rules.py` adds `reconcile-node`, with fresh hostname validation,
  bounded canonical targets, strict desired state 0/1, the legacy transaction
  lock, and failure when an enabled source has no live rule. Existing strict
  single-source behavior remains separate.

The latest completed commands passed 42 planner/snapshot tests
(`/tmp/r42-snat-coverage-readback-green.log`) and 18 node-reconciliation/legacy
tests (`/tmp/r42-snat-node-reconcile-green.log`). They overlap with earlier
checks; these are command counts, not a combined suite total. The pre-existing
pytest asyncio default-loop deprecation warning remains.

## Bounded controller completion wiring

The continuation after `39072d0` wires `apply_network_sdn.yaml` to require saved
snapshots and idle task baselines for all mapped nodes, revalidate membership
before PUT, wait for the parent, and then wait for one verified successful
`srvreload` / `networking` worker on every node. Failed, missing, unfinished,
ambiguous or unreadable workers stop the flow before any NAT cleanup. Public
apply output includes the verified `node_reloads` identities. Restoration
requires the completion fact, which is cleared before a new snapshot or apply.
Reconciliation can also run from a complete stable snapshot when no apply was
attempted, after fresh membership, task visibility and reload-history checks.
That path never claims apply completion.

The explicit facts are `network_snat_snapshot_verified`,
`network_snat_apply_attempted` and `network_snat_apply_verified`. Snapshot entry
sets them to `false`, `null` and `false`; only successful collection and idle
baseline checks on every node set snapshot verification to `true` and apply
attempted to `false`. Entering apply sets attempted to `true` before its guards
or requests, and only verified parent and node completion sets apply verified
to `true`. An unknown state, failed new snapshot or attempted but unverified
apply cannot authorize stable reconciliation. Saved node key coverage must
also be complete. Stable reconciliation rereads zone membership instead of
reusing the snapshot's saved zone inventory.

The stable no-apply regressions first failed at the former completion guard
(`/tmp/r42-snat-no-apply-red.log`); a separate zone-drift regression then showed
that saved membership could incorrectly authorize reconciliation
(`/tmp/r42-snat-no-apply-zone-red.log`). The final focused command passed all
61 tests, including 27 real local Ansible cases, in 248.79 seconds:
`pytest -q tests/test_snat_cluster_ansible.py tests/test_snat_cluster.py tests/test_snat_node_reconcile.py`.
Log: `/tmp/r42-snat-no-apply-green.log`. The caller-task/fixture-role hooks also
passed a real stable-preservation run (`/tmp/r42-snat-caller-hook-green.log`).
Scoped Ruff, formatting and `git diff --check` passed. The existing pytest
asyncio configuration warning remains. These checks do not establish paired
composite or live cluster acceptance.

`check_snat_audit.yaml` requires the authenticated token's effective
`Sys.Audit` privilege on each `/nodes/<node>` path before relying on task
history. The permissions response maps privilege names to propagation flags;
a present privilege with value `0` is valid. Visibility is rechecked when
waiting and before cleanup. Checking only `/cluster/status` is insufficient:
an audit privilege on `/` need not propagate to node paths.

The recent-history baseline now requires no networking task since the
node-local snapshot timestamp. A completed task in that interval also makes
the snapshot stale. Idle/history checks run again immediately before PUT.
Proxmox timestamps have seconds resolution and `since` is inclusive, so a
same-second completed task can conservatively require a fresh snapshot after
the node is idle. No write is authorized on that refusal.

`tests/test_snat_cluster_ansible.py` runs the actual Ansible task graph and
Python helpers with a private API/rule fixture. It verifies delayed completion,
failed/missing/ambiguous workers, all-node cleanup ordering, incomplete/offline/
wrong-host mapping, effective task visibility, intervening reloads, direct
cleanup refusal and the legitimate single-node default. The fixture's Python
hostname shim was corrected to emulate `python3 -c` argument handling; the
earlier partial checkpoint had failed before reaching apply. The initial
completion run passed 10 cases; both subsequently reproduced visibility/drift
regressions passed after their fixes. The final focused command passed all
43 tests (14 real local Ansible cases and 29 planner/helper cases) in 132.81s:
`pytest -q tests/test_snat_cluster_ansible.py tests/test_snat_cluster.py`.
Log: `/tmp/r42-snat-apply-completion-final.log`. Scoped Ruff and `git diff
--check` passed. The existing pytest asyncio configuration warning remains.

## Required next implementation

1. Wire the playbooks composites to supply desired `{source,vnet,zone,want}`
   entries and new-zone membership at snapshot, calculate missing-enabled
   conditions across all applicable nodes, and call
   `network_reconcile_snat_sources` instead of the old primary-node operation.
   Internet composites need an authoritative VNet-to-zone binding. Require
   actual cluster snapshot coverage before their first write, so old controller
   versions cannot silently ignore the new contract.
2. Adapt older single-node action fixtures to the new included files/API reads
   and output. Run matched composite orchestration tests and update capability
   markers/parameter docs only after that integration passes. This bounded
   controller continuation does not claim a passing full controller suite or
   a compatible playbooks release.
3. Review node mapping changes, selected zone membership changes, SSH identity
   expectations and limits before any matched release/acceptance. Inventory
   configuration remains trusted; no discovery of SSH credentials is implied.

An outer xtables lock protects cooperating legacy writers on one host, not an
entire cluster transaction. External configuration writers still need explicit
coordination. nft remains unsupported. Root independently reported read-only
range42 evidence `iptables v1.8.11 (legacy)` on 2026-09-11; this establishes that
target's backend compatibility, not acceptance of this unfinished checkpoint.

The global parent does not expose child UPIDs. Observing one new node worker
after a verified idle baseline is evidence only while external reload writers
are coordinated; it does not cryptographically bind the worker to this apply.
Permission/configuration changes during execution, disappeared task history,
clock rollback, unsupported zones, and partial node failure remain reasons to
stop and inspect. No cross-node atomic rollback is promised. No live node or
multi-node cluster acceptance was performed in this continuation.

## Primary source findings

[Proxmox cluster status](https://github.com/proxmox/pve-manager/blob/master/PVE/API2/Cluster.pm)
requires `Sys.Audit` on `/` and returns complete membership including offline
nodes. [Zone configuration](https://github.com/proxmox/pve-network/blob/master/src/PVE/API2/Network/SDN/Zones.pm)
defines the node restriction; an omitted restriction means all nodes.

[Global SDN reload](https://github.com/proxmox/pve-network/blob/master/src/PVE/API2/Network/SDN.pm)
launches each node worker without waiting for all of them: the parent UPID alone
does not prove completion. [The network endpoint](https://github.com/proxmox/pve-manager/blob/master/PVE/API2/Network.pm)
uses task type `srvreload`, id `networking`.
[Node task listing](https://github.com/proxmox/pve-manager/blob/master/PVE/API2/Tasks.pm)
supports `source=active|all`, `typefilter`, `since` and bounded `limit`; propagated
`Sys.Audit` is needed to see other users' workers.
[Effective permissions](https://github.com/proxmox/pve-access-control/blob/master/src/PVE/API2/AccessControl.pm)
can be queried for the current token at an exact ACL path; values describe
propagation, while key presence establishes the privilege on that path.
