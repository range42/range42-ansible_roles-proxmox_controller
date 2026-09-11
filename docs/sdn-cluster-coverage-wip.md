# Incomplete cluster coverage checkpoint — do not activate

This continuation starts at controller `e7a7332` in
`/tmp/r42-sdn-controller-preservation-next-wave`. Paired playbooks started at
`fb536e79ea969de6378e3cd272f75b878b0a03b3` in
`/tmp/r42-sdn-preservation-next-wave`; the subsequent bounded composite
continuation is recorded below and in that checkout's
`docs/sdn-cluster-composites.md`. No live SSH, firewall, SDN or release mutation
was performed.

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

## Zone-creation request correction

Independent paired review found that the planner accepts a list of new-zone
members but `add_network_sdn_zone.yaml` forwarded that list into JSON `nodes`.
The API requires a node-list string. Creation now reads authoritative cluster
membership and reuses the same member validation as planning. It emits a
comma-separated string for a subset and omits `nodes` for empty/all-node scope.
The reported `zone_nodes` uses the same encoded value. If snapshot facts are
present, the current cluster and requested set must match that verified
snapshot's new-zone intent before POST; a stale or incomplete proof is refused.
The raw zone-creation action consequently also requires readable, online,
quorate cluster membership before creating a declaration.

Eleven actual Ansible/loopback TLS request tests cover list/string/empty/null/
all-node encoding, invalid or duplicate membership and changed snapshot scope.
Ten failed before implementation while the existing subset-string case passed
(`/tmp/r42-zone-membership-red.log`). The fixed command passed 40 tests, including
those eleven requests and 29 existing planner regressions, in 23.34 seconds
(`/tmp/r42-zone-membership-green.log`). Three paired bootstrap tests also execute
the actual creation task and inspect the HTTP JSON body against the saved
source membership: list and empty inputs failed before the fix; all three now
pass in 30.00 seconds (`/tmp/r42-paired-zone-green.log`). This is local request
validation only; no live zone was created. Previous activation limits remain.

## Missing-quorum evidence correction

Review of the reused cluster validator found that two online node rows without
any cluster row could pass, so those responses did not prove quorum. The shared
validator now requires exactly one cluster record for a multi-node deployment,
a boolean/integer true quorum value, and an integer node count matching the
complete node inventory. Missing, incomplete, duplicate, nonquorate, wrongly
typed or count-mismatched records are refused. One standalone node may still
have no cluster record. The same validator guards planning, snapshot/apply/
reconciliation revalidation and zone creation.

Fixtures now return a complete cluster record for multi-node success cases.
Negative request tests explicitly omit or corrupt that record. Before the fix,
six planner/request cases failed (missing quorum evidence and accepted floating
point quorum/node-count values), while ten focused checks passed. A separate
paired bootstrap regression showed zone POST could proceed after fresh quorum
evidence disappeared. Red logs: `/tmp/r42-quorum-red.log` and
`/tmp/r42-paired-quorum-red.log`. The final affected command passed 82 checks
in 272.46 seconds: 36 planner cases, 19 actual TLS zone-request cases, and all
27 existing real-Ansible snapshot/apply/reconcile cases. Log:
`/tmp/r42-quorum-green.log`. All 18 affected paired/composite checks passed in
113.57 seconds (`/tmp/r42-paired-quorum-green.log`). Scoped Ruff/formatting and
whitespace checks passed; independent review found no further issue. The existing
pytest asyncio configuration warning remains. No live calls were performed.

The zone wire schema uses the `pve-node-list` string option in
[Proxmox JSONSchema.pm](https://github.com/proxmox/pve-common/blob/master/src/PVE/JSONSchema.pm),
consumed by the `nodes` property in
[the SDN zone plugin](https://github.com/proxmox/pve-network/blob/master/src/PVE/Network/SDN/Zones/Plugin.pm).

## Explicit read-only source counts

The paired standalone reconciliation continuation adds `count-source` to
`snat_cluster.py` and the `network_count_snat_source` role action. It validates
canonical IPv4 source, complete unique node coverage, snapshot identities and
positive observation timestamps, strict nonnegative counts, and the supplied
verified/no-apply fact state. It returns only source, primary node and per-node
count/timestamp fields. It executes no iptables command and does not independently
enforce receipt age. The standalone caller ensures freshness by clearing old
facts and immediately collecting a new complete cluster snapshot before calling
it; node observations are not an atomic cluster measurement.

WANT99 uses this action even after a declaration has been deleted. WANT0/1 in
the paired bundle resolves authoritative source/VNet/zone bindings, requires
matching declared SNAT, refuses missing enabled rules before cleanup and reuses
the existing stable reconciliation gate. The older strict single-source helper
continues to accept only 0/1; no arbitrary high-value mutation path is introduced.

The positive helper regression failed before the operation existed. Twelve
new count cases plus 36 existing planner cases passed in 1.88 seconds
(`/tmp/r42-snat-counts-green.log`). All 23 paired standalone boundary/actual
Ansible cases passed in 77.94 seconds
(`/tmp/r42-standalone-reconcile-final.log`), including 105-rule read-only counts,
post-deletion inspection, invalid/missing coverage and preservation of unrelated
and nonmember rules. The role fixture gains only an optional initial count and
the new action dispatcher. Three existing real-Ansible default/stable flow
checks also passed in 35.70 seconds, with 24 deselected
(`/tmp/r42-standalone-controller-dispatch-check.log`, handle64685 exit0).
Scoped Ruff, formatting and whitespace checks pass. Independent review found
no mutation-scope issue. No live operation or capability marker changed.

## Required next implementation

1. Completed for the five bootstrap/internet/apply composites in the paired
   continuation: exact `{source,vnet,zone,want}` intent, new-zone membership,
   authoritative VNet-zone bindings, all-applicable-node missing-enabled checks,
   plural reconciliation and complete snapshot proof before first write.
   Twelve new composite/planner regressions, sixteen adapted existing scoped
   cases, and two paired actual-controller cases pass. The paired stable and
   verified-apply cases preserve nonmember and unrelated rule identities/order.
   The fixture dispatcher was narrowed to the actual production action list so
   unrelated list operations do not expand preservation tasks prematurely.
2. Remaining older controller action fixtures need adaptation and full matched
   release review. Subsequent paired work adapts `bootstrap.sdn_vnet` and the
   standalone `reconcile.snat_rules` entrypoint. `delete.all` still uses the
   legacy primary-node cleanup flow and can delete declarations before an
   unproven apply is refused. It requires retained pre-delete source and node
   scope, explicit attachment/pending-change policy and preservation before
   activation. Capability markers remain unchanged. This bounded continuation
   does not claim a passing full controller suite or a deployable release.
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
