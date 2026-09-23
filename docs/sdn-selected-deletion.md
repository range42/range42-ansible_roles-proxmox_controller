# Selected VNet deletion scope

This source extends `snat_cluster.py`'s existing `delete-scope`/`read-delete`
contract with optional `vnets`. Absent/null preserves whole-zone selection;
a supplied list must contain 1–64 unique valid VNet names. Existing selected
VNets must belong to the explicit `zone`; a foreign-zone binding is refused.
The controller role passes `sdn_delete_vnets` through the fixed read collector.

The collector still obtains complete root-visible global current/pending SDN
and QEMU/LXC inventories, rechecks guest discovery, and returns the same
API/SSH cluster identity proof. Selection is applied only after complete
inventory validation. An unselected VNet in the same zone may retain guest
attachments. A selected current or pending NIC attachment blocks deletion.

Selected mode records `selection=vnets`, sorted `requested_vnets`,
`absent_vnets` and `objects_present`; actual `vnets`, `subnets` and desired source
intent contain only existing selected objects. Source CIDRs remain canonical
API fields, with complete cluster-wide uniqueness checks; neither names nor
subnet IDs imply a CIDR. Missing selected objects supply no orphan-rule scope.

The selected remaining-inventory hash retains the zone and every unselected
VNet/subnet. The paired playbooks use the existing cluster snapshots, apply,
reconcile, exact preservation and journal flow. The journal implementation is
unchanged: its retained scope includes selection, while its cluster-wide
incomplete-record gate refuses another attempt/selection before mutations.
Automatic partial-deletion resume is still unsupported.

The all-zone default, 120s collector deadline, two-command guest-read batch,
output/process cleanup bounds, mandatory complete online/quorate coverage,
CA identity binding and legacy-iptables-only mutation policy are unchanged.
Read-only scope verification does not establish an atomic remote transaction;
external SDN/NIC/rule writers still require coordination.

Local source evidence:

- 52 selected and original scope cases passed (`/tmp/r42-sdn-selected-scope-green.log`),
  after nine new selection failures were reproduced against the old helper.
- Five actual collector/Ansible role cases passed
  (`/tmp/r42-sdn-selected-role-green.log`), covering explicit absent selection,
  ordinary all-zone selection and matching/mismatched API/SSH identities.
- Paired mutation/preview/CLI outcomes are recorded in the matching playbooks
  `docs/sdn-selected-delete-source-checkpoint.md`.

This isolated source starts at controller `da3f540`; it changes no shared or
live installation. Earlier read-only 47-guest collector acceptance remains
historical evidence for its exact former helper, not mutation acceptance for
this selected adapter.
