# Table of Contents

- [Project Overview](#Project-Overview)
- [Repository Content](#Repository-Content)
- [Contributing](#Contributing)
- [License](#License)

---

# Project Overview

**RANGE42** is a modular cyber range platform designed for real-world readiness.
We build, deploy, and document offensive, defensive, and hybrid cyber training environments using reproducible, infrastructure-as-code methodologies.

## What we build

- Proxmox-based cyber ranges with dynamic catalog 
- Ansible roles for automated deployments (Wazuh, Kong, Docker, etc.)
- Private APIs for range orchestration and telemetry
- Developer and testing toolkits and JSON transformers for automation pipelines
- ...

## Repository Overview

- **RANGE42 deployer UI** : A web interface to visually design infrastructure schemas and trigger deployments.
- **RANGE42 deployer backend API** : Orchestrates deployments by executing playbooks and bundles from the catalog.
- **RANGE42 catalog** : A collection of Ansible roles and Docker/Docker Compose stacks, forming deployable bundles.
- **RANGE42 playbooks** : Centralized playbooks that can be invoked by the backend or CLI.
- **RANGE42 proxmox role** : An Ansible role for controlling Proxmox nodes via the Proxmox API.
- **RANGE42 devkit** : Helper scripts for testing, debugging, and development workflows.
- **RANGE42 kong API gateway** : A network service in front of the backend API, handling authentication, ACLs, and access control policies.
- **RANGE42 swagger API spec** : OpenAPI/Swagger JSON definition of the backend API.

### Putting it all together

This repository contains an ansible role for interacting with the Proxmox API to manage one or multiple nodes, perform automated actions, and return results in JSON format.

---

# Repository Content

This repository contains an ansible role for interacting with the proxmox API. It enables automated management of nodes, VMs, containers, storage, networking and firewall configurations and can return results in JSON format.

Current Capabilities (non-exhaustive list) : 

Virtual Machines & Containers : 

 - Create and manage Virtual Machines (QEMU) and LXC containers
 - Control lifecycle: start, stop, pause, resume, reset
 - Collect VM configuration: general, CPU, RAM, CD-ROM, tags, etc.
 - List existing VMs and containers
 - Convert VMs to templates

Templates & Cloud-Init

 - Create new VM templates
 - Deploy VMs using Cloud-Init
 - Define Cloud-Init variables
 - Partial support for templates and VM provisioning

Snapshots

 - Create and revert snapshots for VMs and LXC containers
 - List available snapshots for a VM or LXC

Storage

 - Partial storage management
 - List available ISOs
 - Download ISOs to storage
 - ...

Networking

 - Add and manage network interfaces for VMs
 - Add and manage network interfaces for nodes
 - List network interfaces on VMs and nodes
 - ...

Firewall (proxmox stack)

 - Enable or disable firewall at VM, node, and datacenter levels
 - Configure iptables firewall rules
 - List existing firewall rules

## Contributing

This is a collaborative initiative, developed for applied security training, community integration, and internal capability building.
We use centralized community health files in Range42 community health.

## License

- GPL-3.0 license

