packer {
  required_plugins {
    qemu = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "ubuntu_iso_url" {
  type    = string
  default = "https://releases.ubuntu.com/24.04/ubuntu-24.04-live-server-amd64.iso"
}

variable "ubuntu_iso_checksum" {
  type    = string
  default = "sha256:none"
}

variable "hookmon_version" {
  type    = string
  default = "dev"
}

source "qemu" "hookmon" {
  iso_url          = var.ubuntu_iso_url
  iso_checksum     = var.ubuntu_iso_checksum
  output_directory = "output-hookmon-qcow2"
  vm_name          = "hookmon-${var.hookmon_version}.qcow2"
  format           = "qcow2"
  disk_size        = "20G"
  memory           = 2048
  cpus             = 2

  ssh_username     = "hookmon"
  ssh_password     = "hookmon"
  ssh_timeout      = "30m"

  shutdown_command = "echo 'hookmon' | sudo -S shutdown -P now"

  boot_command = [
    "<esc><wait>",
    "autoinstall ds=nocloud;",
    "<enter>"
  ]

  http_directory = "../iso"
}

build {
  sources = ["source.qemu.hookmon"]

  provisioner "shell" {
    scripts = [
      "scripts/base.sh",
      "scripts/postgres.sh",
      "scripts/hookmon.sh",
      "scripts/nginx.sh",
      "scripts/firstboot.sh",
    ]
    execute_command = "echo 'hookmon' | sudo -S bash '{{ .Path }}'"
  }
}
