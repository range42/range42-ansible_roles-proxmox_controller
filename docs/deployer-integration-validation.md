# SDN deployer integration validation

Base: `feat-sdn-implementation` at `c1713569d2396ea91b2e55fe1348d402613254a6`.
This integration preserves that branch's SDN/firewall work and applies three reviewed fixes:

- [PR 105](https://github.com/range42/range42-ansible_roles-proxmox_controller/pull/105): import the cloud image unchanged, attach it, then grow the VM-owned disk with `qm resize`. Repeating the import workflow does not reimport or resize an already matching disk.
- [PR 103](https://github.com/range42/range42-ansible_roles-proxmox_controller/pull/103): write an explicit net0 MAC with bridge changes. The caller's MAC takes precedence; otherwise use the deterministic VMID-derived MAC.
- [PR 101](https://github.com/range42/range42-ansible_roles-proxmox_controller/pull/101), ISO portion adapted: inspect the selected storage through `pvesm path`, reuse a matching checksum, replace stale images, pass the checksum to Proxmox and await download completion. Preserve TLS verification and support `RANGE42_PROXMOX_CA_FILE`. Unrelated `cicustom` and ignore-file changes are excluded.

Validation uses actual Ansible task execution with local command/API substitutes; no live hypervisor is modified. Install `ansible-core`, `pytest`, and `cryptography` in one environment, then run:

```sh
python -m pytest tests/test_cloud_image_resize.py tests/test_iso_download.py -q
```

The four cases pass: source bytes remain unchanged, repeat imports are inert, verified images are cached, stale images are repaired and absent images are downloaded. Storage checks use a custom path rather than `/var/lib/vz`. ISO tests use a local HTTPS API with a generated trusted CA.

The companion range42-playbooks `tests/test_vm_bootstrap_extensions.py` runs the real controller role with `RANGE42_CONTROLLER_TEST_ROOT` pointing to this checkout. Its six cases cover deployment ownership, secondary NIC/resource changes, safe disk growth/rejections and caller-supplied primary MAC preservation.

Checksum discovery supports published SHA256SUMS, then SHA512SUMS when SHA256SUMS is unavailable. Matching entries use the original URL basename. If no checksum is published, an existing image is reused with an explicit unverified message, and a missing image downloads without checksum verification. This is integrity checking against the same origin, not signature verification. Download completion waits at most about ten minutes; longer or failed tasks stop template creation. Live download/storage and guest disk expansion still require the shared-lab smoke test.

## Exact live SNAT rule matching

The runtime review found that both SNAT actions treated every source-specific POSTROUTING rule as a NAT rule. Cleanup could delete ACCEPT/LOG entries, and an ACCEPT entry could falsely satisfy the enabled count. Quoted comments were split during deletion and could be misread as source/target options.

Both actions now invoke the same bounded Python3 helper through Ansible's argv-based command module. It parses `iptables -S` quoting with `shlex`, selects an exact non-negated IPv4 source and SNAT/MASQUERADE jump, and preserves original argument boundaries when deleting. Read errors, refused writes, invalid desired states, and a nondecreasing rule count fail. Reconciliation deletes surplus matching rules only; it never invents a missing NAT rule. The read-only action omits ACCEPT/LOG, source-free and negated-source rules.

The controller role advertises `runtime-capabilities.json` with `snat_rule_matching: exact_source_nat_target_v1`. Reconciliation emits that same field alongside its existing integer counts, selected node and SSH host. Backend runtime operations must require this marker and reject older source-only count evidence.

`tests/test_snat_rules.py` executes both actual task commands against a private fake iptables table. Thirteen cases cover same-source ACCEPT/LOG preservation, broader/narrower CIDRs, negated sources, quoted and escaped comments, exact SNAT/MASQUERADE enable deduplication and disable, read failures, rejected deletions and invalid input. Three cases execute the full real Ansible action block and verify its emitted result shape. No test changes a live host firewall. The host still requires Python3 and iptables, and external writers must coordinate independently; the helper does not provide an atomic global network transaction or an end-to-end forwarding test.
