# Isolated template creation contract

This additive controller change is based on installed revision
`99fd63cfcf65a52eaed05af4404f81522acfaa52`. It supports the reviewed isolated
Noble builder; it does not expose template creation through the deployer UI.

`vm_create` accepts an optional `vm_description` and includes it in the atomic
create POST. With `vm_create_require_absent: true`, an existing or unreadable
VM status is refused instead of being silently adopted. An atomic create
conflict remains a failure. Existing callers keep the previous existing-VM
no-op behavior when this option is absent or false.

Strict mode requires `range42-template-build:<32 lowercase hex>` and optionally
a second `range42-template-plan:<64 lowercase hex>` line. The paired builder
uses both lines and checks them after creation and before later mutations.
`include/vm/vm_create_capabilities.yaml` advertises these guards so the builder
fails before writes when paired with an older role installation.

This primitive is not an allocation ledger or a complete ownership workflow.
The isolated caller must first prove cluster-wide ID absence using privileged
SSH, compare API/SSH cluster CA identities, and check node, storage and source
image scope. Proxmox reports a missing VM status as HTTP500; accepting that
status is only appropriate after the caller's authoritative absence check.
The primitive alone does not distinguish every possible server-side HTTP500.
External Proxmox writers still require coordination.

Validation: eight tests execute the actual Ansible create task against a local
TLS HTTP fixture. They cover atomic marker/plan retention, existing/unreadable
target refusal, create conflict and legacy existing-target no-op. The initial
guard/marker regressions reproduced five failures; the plan-line regression
reproduced one more failure. Final focused run passed8tests in13.10seconds;
scoped Ruff and diff checks passed. No live VM or template was created.
