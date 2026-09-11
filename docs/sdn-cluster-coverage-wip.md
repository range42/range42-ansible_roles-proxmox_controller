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

## Partial Ansible wiring — not verified end to end

`plan_snat_coverage.yaml`, `snapshot_snat_nodes.yaml`,
`snat_reload_baseline.yaml`, and the preservation action now contain initial
coverage, per-node snapshot, per-node reconciliation and restoration wiring.
This wiring has NOT had its green integration run. Existing single-node action
fixtures must be adapted to the new included files/API reads and public output.

`tests/test_snat_cluster_ansible.py` provides a disposable two-node fixture with
real Ansible/Python helpers and a private fake API/rule table. Its initial red
run failed two expected cases (successful complete orchestration and failed
second-node reload handling); three refusal cases passed. No run was started
after the partial task wiring. Log: `/tmp/r42-snat-cluster-ansible-red.log`.

## Required next implementation

1. Complete `apply_network_sdn.yaml`: revalidate coverage before PUT, then wait
   for one new successful `srvreload` task with id `networking` on EVERY mapped
   node after the parent finishes. Compare against the saved baseline and
   validate helper completion evidence before any node cleanup. Missing,
   ambiguous, failed or timed-out node workers must fail the operation.
   Current task wiring does not yet invoke those completion helpers.
2. Wire the playbooks composites to supply desired `{source,vnet,zone,want}`
   entries and new-zone membership at snapshot, calculate missing-enabled
   conditions across all applicable nodes, and call
   `network_reconcile_snat_sources` instead of the old primary-node operation.
   Internet composites need an authoritative VNet-to-zone binding. Require
   actual cluster snapshot coverage before their first write, so old controller
   versions cannot silently ignore the new contract.
3. Finish the local Ansible cases: two nodes, delayed and failed second-node
   workers, incomplete/offline/wrong-host mappings, active or ambiguous reloads,
   unchanged single-node behavior, and preservation of unrelated node rules.
   Update compatibility markers/parameter docs only after matching tests pass.
4. Review node mapping changes, selected zone membership changes, SSH identity
   expectations and limits before any matched release/acceptance. Inventory
   configuration remains trusted; no discovery of SSH credentials is implied.

An outer xtables lock protects cooperating legacy writers on one host, not an
entire cluster transaction. External configuration writers still need explicit
coordination. nft remains unsupported. Root independently reported read-only
range42 evidence `iptables v1.8.11 (legacy)` on 2026-09-11; this establishes that
target's backend compatibility, not acceptance of this unfinished checkpoint.

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
