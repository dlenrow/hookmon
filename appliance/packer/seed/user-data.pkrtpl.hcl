#cloud-config
# NoCloud seed for the Packer build only (hookmon.pkr.hcl serves it). It
# makes the temporary build user that Packer logs in as. The shutdown
# command deletes that user, and cleanup.sh removes cloud-init's state, so
# none of this is in the finished image.
users:
  - name: packer
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: "${password}"
ssh_pwauth: true
package_update: false
package_upgrade: false
