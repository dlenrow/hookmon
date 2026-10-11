# HookMon appliance image: Ubuntu 24.04 LTS with hookmon-server, the
# dashboard and PostgreSQL 16, built with the QEMU builder on a Linux host
# with KVM. `make appliance-qcow2` builds the inputs from this tree and runs
# this template; `make appliance-vhd` and `make appliance-ova` convert the
# result (convert.sh).
#
# Base: the Ubuntu 24.04 cloud image, not the live-server ISO. It boots
# straight to SSH through a NoCloud seed (seed/user-data.pkrtpl.hcl, served
# by Packer's HTTP server and named on the SMBIOS serial), so there is no
# installer to drive with boot_command keystrokes. The build takes minutes
# instead of a full autoinstall, the image starts from Canonical's own
# cloud build (cloud-init, growpart, the virtual kernel, open-vm-tools), and
# cloud-init stays in the image so platforms that offer a datasource
# (OpenStack, Proxmox, NoCloud, VMware OVF properties) can inject SSH keys.
#
# Each appliance makes its own CA, certificates, tokens and database
# password on first boot (files/hookmon-firstboot). The image holds none.

packer {
  required_version = ">= 1.11.0"
  required_plugins {
    qemu = {
      version = "= 1.1.6"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "base_image_url" {
  type = string
  # A dated release directory, so this URL and the checksum below stay valid
  # together. To move to a newer image, change both (the directory's
  # SHA256SUMS file has the checksum).
  default = "https://cloud-images.ubuntu.com/releases/noble/release-20260926/ubuntu-24.04-server-cloudimg-amd64.img"
}

variable "base_image_checksum" {
  type    = string
  default = "sha256:6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2"
}

variable "server_binary" {
  type        = string
  description = "hookmon-server built for linux/amd64. Default: bin/linux-amd64/hookmon-server (make appliance-server)."
  default     = ""
}

variable "dashboard_dir" {
  type        = string
  description = "The built dashboard. Default: dashboard/dist (make build-dashboard)."
  default     = ""
}

variable "disk_size" {
  type    = string
  default = "20G"
}

variable "accelerator" {
  type    = string
  default = "kvm"
}

locals {
  repo          = "${path.root}/../.."
  server_binary = var.server_binary != "" ? var.server_binary : "${local.repo}/bin/linux-amd64/hookmon-server"
  dashboard_dir = var.dashboard_dir != "" ? var.dashboard_dir : "${local.repo}/dashboard/dist"
  role_files    = "${path.root}/../ansible/roles/hookmon_server/files"

  # Password of the temporary build user. It exists only while Packer runs:
  # the shutdown command deletes the user, and cleanup.sh turns password
  # logins off.
  build_password = uuidv4()
}

source "qemu" "hookmon" {
  iso_url      = var.base_image_url
  iso_checksum = var.base_image_checksum
  disk_image   = true

  output_directory   = "${path.root}/output"
  vm_name            = "hookmon-appliance.qcow2"
  format             = "qcow2"
  disk_size          = var.disk_size
  disk_interface     = "virtio"
  disk_discard       = "unmap"
  disk_detect_zeroes = "unmap"
  disk_compression   = true
  net_device         = "virtio-net"
  accelerator        = var.accelerator
  cpu_model          = "host"
  cpus               = 2
  memory             = 2048
  headless           = true

  # Everything the build listens on is bound to the loopback interface.
  vnc_bind_address  = "127.0.0.1"
  http_bind_address = "127.0.0.1"
  http_port_min     = 42300
  http_port_max     = 42399
  host_port_min     = 42400
  host_port_max     = 42499
  http_content = {
    "/meta-data" = "instance-id: hookmon-build\nlocal-hostname: hookmon\n"
    "/user-data" = templatefile("${path.root}/seed/user-data.pkrtpl.hcl", { password = local.build_password })
  }
  qemuargs = [
    # The guest reaches Packer's HTTP server at 10.0.2.2 (user-mode
    # networking maps it to the host's 127.0.0.1).
    ["-smbios", "type=1,serial=ds=nocloud;s=http://10.0.2.2:{{ .HTTPPort }}/"],
    # Packer's default forward listens on every interface; this one only
    # on the loopback.
    ["-netdev", "user,id=user.0,hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:22"],
    ["-device", "virtio-net,netdev=user.0"],
  ]

  communicator = "ssh"
  ssh_username = "packer"
  ssh_password = local.build_password
  ssh_timeout  = "20m"

  shutdown_command = "sudo sh -c 'userdel -rf packer; rm -f /etc/sudoers.d/90-cloud-init-users; shutdown -P now'"
}

build {
  sources = ["source.qemu.hookmon"]

  provisioner "shell" {
    inline = ["mkdir -p /tmp/hookmon-upload/dashboard /tmp/hookmon-upload/files"]
  }

  provisioner "file" {
    source      = local.server_binary
    destination = "/tmp/hookmon-upload/hookmon-server"
  }

  provisioner "file" {
    source      = "${local.dashboard_dir}/"
    destination = "/tmp/hookmon-upload/dashboard"
  }

  provisioner "file" {
    sources = [
      "${local.repo}/deploy/appliance/hookmon-init.sh",
      "${local.role_files}/hookmon-server.service",
      "${local.role_files}/hookmon-db-setup",
      "${path.root}/files/hookmon-firstboot",
      "${path.root}/files/hookmon-firstboot.service",
      "${path.root}/files/01-hookmon.yaml",
      "${path.root}/files/99-hookmon-network.cfg",
      "${path.root}/files/10-hookmon.conf",
      "${path.root}/files/hookmon-hostkeys.conf",
    ]
    destination = "/tmp/hookmon-upload/files/"
  }

  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; sudo {{ .Vars }} {{ .Path }}"
    scripts = [
      "${path.root}/scripts/base.sh",
      "${path.root}/scripts/postgres.sh",
      "${path.root}/scripts/hookmon.sh",
      "${path.root}/scripts/firstboot.sh",
      "${path.root}/scripts/cleanup.sh",
    ]
  }
}
