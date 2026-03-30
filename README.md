# range42-ansible_roles-proxmox_controller

Custom Ansible role for managing Proxmox nodes via the REST API.
Part of the [range42](https://github.com/range42/range42) platform.

---

## Why a custom role?

This role is a thin wrapper over the Proxmox REST API using the `uri` module.
It gives full control over the API surface — VM lifecycle, firewall rules,
cloud-init, snapshots, networking, storage — through a single action-driven
interface. One role, one variable (`proxmox_vm_action`), predictable behavior.

---

## How it works

The role is action-driven. You set the variable `proxmox_vm_action` to the
action you want, pass the required variables, and the role dispatches to the
right task file:

```yaml
- name: Start a VM
  include_role:
    name: range42-ansible_roles-proxmox_controller
  vars:
    proxmox_vm_action: vm_start
    proxmox_node: "px-testing"
    vm_id: 100
```

```yaml
- name: Create a VM from cloud-init template
  include_role:
    name: range42-ansible_roles-proxmox_controller
  vars:
    proxmox_vm_action: vm_create
    proxmox_node: "px-testing"
    vm_id: 100
    vm_name: "r42.mon-wazuh-01"
    vm_ci_ip: "192.168.42.100/24"
    vm_ci_gateway: "192.168.42.1"
    vm_ci_dns_ips: "1.1.1.1"
    # ... see defaults/main.yml for all variables
```

```yaml
- name: Snapshot a VM before changes
  include_role:
    name: range42-ansible_roles-proxmox_controller
  vars:
    proxmox_vm_action: snapshot_vm_create
    proxmox_node: "px-testing"
    vm_id: 100
    vm_snapshot_description: "base"
```

---

## Available actions

### Virtual Machines (`vm_*`)

| Action | Description |
|--------|-------------|
| `vm_create` | Create a VM (QEMU) |
| `vm_delete` | Delete a VM |
| `vm_clone` | Clone a VM |
| `vm_start` | Start a VM |
| `vm_stop` | Graceful stop |
| `vm_stop_force` | Force stop |
| `vm_pause` | Pause a VM |
| `vm_resume` | Resume a paused VM |
| `vm_list` | List all VMs on a node |
| `vm_get_config` | Get full VM config |
| `vm_get_config_cpu` | Get CPU config |
| `vm_get_config_ram` | Get RAM config |
| `vm_get_config_cdrom` | Get CD-ROM config |
| `vm_list_usage` | Get VM resource usage |
| `vm_set_tag` | Set tags on a VM |

### LXC Containers (`lxc_*`)

| Action | Description |
|--------|-------------|
| `lxc_create` | Create a container |
| `lxc_delete` | Delete a container |
| `lxc_clone` | Clone a container |
| `lxc_start` | Start a container |
| `lxc_stop` | Graceful stop |
| `lxc_stop_force` | Force stop |
| `lxc_pause` | Pause a container |
| `lxc_resume` | Resume a paused container |
| `lxc_list` | List all containers |
| `lxc_set_tag` | Set tags on a container |

### Snapshots (`snapshot_vm_*`, `snapshot_lxc_*`)

| Action | Description |
|--------|-------------|
| `snapshot_vm_create` | Create VM snapshot |
| `snapshot_vm_revert` | Revert VM to snapshot |
| `snapshot_vm_delete` | Delete VM snapshot |
| `snapshot_vm_list` | List VM snapshots |
| `snapshot_lxc_create` | Create LXC snapshot |
| `snapshot_lxc_revert` | Revert LXC to snapshot |
| `snapshot_lxc_delete` | Delete LXC snapshot |
| `snapshot_lxc_list` | List LXC snapshots |

### Templates & Cloud-Init (`template_*`, `cloudinit_*`)

| Action | Description |
|--------|-------------|
| `template_create` | Create a new VM template |
| `template_convert_vm_to_template` | Convert existing VM to template |
| `template_cloudinit_import_disk` | Import cloud-init disk image |
| `cloudinit_set_variables` | Set cloud-init variables on a VM |

### Storage (`storage_*`)

| Action | Description |
|--------|-------------|
| `storage_list` | List available storage |
| `storage_list_iso` | List ISOs in a storage |
| `storage_list_template` | List templates in a storage |
| `storage_download_iso` | Download ISO to storage |

### Networking (`network_*`)

| Action | Description |
|--------|-------------|
| `network_list_interfaces_vm` | List VM network interfaces |
| `network_add_interfaces_vm` | Add interface to a VM |
| `network_delete_interfaces_vm` | Delete interface from a VM |
| `network_list_interfaces_node` | List node network interfaces |
| `network_add_interfaces_node` | Add interface to a node |
| `network_delete_interfaces_node` | Delete interface from a node |
| `network_list_node_sdn_zones` | List SDN zones on a node |

### Firewall (`firewall_*`)

| Action | Description |
|--------|-------------|
| `firewall_dc_enable` | Enable firewall at datacenter level |
| `firewall_dc_disable` | Disable firewall at datacenter level |
| `firewall_node_enable` | Enable firewall at node level |
| `firewall_node_disable` | Disable firewall at node level |
| `firewall_vm_enable` | Enable firewall on a VM |
| `firewall_vm_disable` | Disable firewall on a VM |
| `firewall_vm_apply_iptables_rule` | Apply iptables rule to a VM |
| `firewall_vm_list_iptables_rule` | List iptables rules on a VM |
| `firewall_vm_delete_iptables_rule` | Delete iptables rule from a VM |
| `firewall_vm_add_iptables_alias` | Add iptables alias on a VM |
| `firewall_vm_list_iptables_alias` | List iptables aliases on a VM |
| `firewall_vm_delete_iptables_alias` | Delete iptables alias from a VM |
| `firewall_vm_enable_default_ssh_rules` | Apply default SSH firewall rules |

### Cluster (`cluster_*`)

| Action | Description |
|--------|-------------|
| `cluster_set_tag` | Set cluster-level tag colors |

---

## Authentication

The role authenticates via Proxmox API token. Required variables:

```yaml
proxmox_api_host: "192.168.1.100"
proxmox_api_port: 8006
proxmox_api_user: "range42@pve"
proxmox_api_token_id: "range42_token"
proxmox_api_token_secret: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # from vault
```

These are typically stored in the Ansible vault and injected automatically
when deploying through range42 playbooks.

---

## Role Structure

```text
roles/range42-ansible_roles-proxmox_controller/
├── defaults/main.yml              # Default variables
├── tasks/
│   ├── main.yml                   # Action dispatcher (proxmox_vm_action → include)
│   └── include/
│       ├── vm/                    # VM lifecycle tasks
│       ├── lxc/                   # LXC container tasks
│       ├── firewall/              # Firewall tasks
│       │   └── alias/             # Firewall alias management
│       ├── snapshot/
│       │   ├── vm/                # VM snapshot tasks
│       │   └── lxc/               # LXC snapshot tasks
│       ├── storage/               # Storage and ISO tasks
│       ├── templates/             # Template and cloud-init tasks
│       ├── network/               # Network interface tasks
│       └── cluster/               # Cluster-level tasks
```

---

## Contributing

GPL-3.0 license
