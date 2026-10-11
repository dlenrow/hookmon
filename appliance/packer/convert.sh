#!/bin/sh
# convert.sh: make the VHD or OVA appliance image from the qcow2 that
# `packer build` wrote to appliance/packer/output. Needs qemu-img and tar.
#
# Usage: appliance/packer/convert.sh vhd|ova [VERSION]
#
#   vhd  output/hookmon-appliance.vhd: a dynamic VHD for Hyper-V. Azure
#        wants a fixed VHD instead:
#          qemu-img convert -O vpc -o subformat=fixed,force_size=on \
#            output/hookmon-appliance.qcow2 hookmon-appliance-fixed.vhd
#   ova  output/hookmon-appliance.ova: an OVF descriptor, a SHA-256 manifest
#        and a streamOptimized VMDK, for VMware. The descriptor carries the
#        cloud-init properties Ubuntu's own OVA has (hostname, public-keys,
#        user-data), so an SSH key can be set at deploy time.
#
# VERSION (default dev) is written into the OVF descriptor.
set -eu

die() {
	echo "convert.sh: $*" >&2
	exit 1
}

[ $# -ge 1 ] || die "usage: convert.sh vhd|ova [VERSION]"
FORMAT=$1
VERSION=${2:-dev}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/output
SRC=$OUT/hookmon-appliance.qcow2
[ -f "$SRC" ] || die "no $SRC; run make appliance-qcow2 first"
command -v qemu-img >/dev/null 2>&1 || die "qemu-img not found (Debian/Ubuntu: apt install qemu-utils)"

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

case $FORMAT in
vhd)
	qemu-img convert -O vpc -o subformat=dynamic,force_size=on "$SRC" "$OUT/hookmon-appliance.vhd.tmp"
	mv -f "$OUT/hookmon-appliance.vhd.tmp" "$OUT/hookmon-appliance.vhd"
	echo "convert.sh: wrote $OUT/hookmon-appliance.vhd"
	;;
ova)
	WORK=$(mktemp -d "$OUT/ova.XXXXXX")
	trap 'rm -rf "$WORK"' EXIT
	NAME=hookmon-appliance
	DISK=$NAME-disk1.vmdk
	qemu-img convert -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic "$SRC" "$WORK/$DISK"
	CAPACITY=$(qemu-img info --output=json "$SRC" | sed -n 's/.*"virtual-size": *\([0-9]*\).*/\1/p' | head -n 1)
	[ -n "$CAPACITY" ] || die "cannot read the virtual size of $SRC"
	DISK_SIZE=$(wc -c <"$WORK/$DISK" | tr -d ' ')
	cat >"$WORK/$NAME.ovf" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!-- HookMon appliance $VERSION. Written by appliance/packer/convert.sh,
     modelled on the descriptor in Ubuntu's 24.04 cloud image OVA. -->
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vmw="http://www.vmware.com/schema/ovf" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:href="$DISK" ovf:id="file1" ovf:size="$DISK_SIZE"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="$CAPACITY" ovf:capacityAllocationUnits="byte" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="VM Network">
      <Description>The VM Network network</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="$NAME">
    <Info>HookMon appliance</Info>
    <Name>$NAME</Name>
    <OperatingSystemSection ovf:id="94" vmw:osType="ubuntu64Guest">
      <Info>The kind of installed guest operating system</Info>
      <Description>Ubuntu Linux (64-bit)</Description>
    </OperatingSystemSection>
    <ProductSection ovf:required="false">
      <Info>cloud-init customization (OVF datasource)</Info>
      <Product>HookMon appliance</Product>
      <Version>$VERSION</Version>
      <Property ovf:key="instance-id" ovf:type="string" ovf:userConfigurable="true" ovf:value="id-ovf">
        <Label>A unique instance ID for this instance</Label>
        <Description>cloud-init runs its first-boot steps once per instance ID.</Description>
      </Property>
      <Property ovf:key="hostname" ovf:type="string" ovf:userConfigurable="true" ovf:value="hookmon">
        <Label>Hostname</Label>
        <Description>The appliance's hostname. The server certificate is made for this name on first boot.</Description>
      </Property>
      <Property ovf:key="public-keys" ovf:type="string" ovf:userConfigurable="true" ovf:value="">
        <Label>SSH public keys</Label>
        <Description>Added to the authorized_keys of the default user, ubuntu. The appliance has no password logins.</Description>
      </Property>
      <Property ovf:key="user-data" ovf:type="string" ovf:userConfigurable="true" ovf:value="">
        <Label>Encoded user-data</Label>
        <Description>Optional base64-encoded cloud-init user-data.</Description>
      </Property>
    </ProductSection>
    <VirtualHardwareSection ovf:transport="iso">
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>$NAME</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-10</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>2 virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>2</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>4096MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>4096</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>SCSI Controller 0</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>VirtualSCSI</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>IDE Controller</rasd:Description>
        <rasd:ElementName>VirtualIDEController 0</rasd:ElementName>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:ResourceType>5</rasd:ResourceType>
      </Item>
      <Item ovf:required="false">
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>false</rasd:AutomaticAllocation>
        <rasd:ElementName>CD-ROM 1</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:Parent>4</rasd:Parent>
        <rasd:ResourceSubType>vmware.cdrom.remotepassthrough</rasd:ResourceSubType>
        <rasd:ResourceType>15</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>Hard Disk 1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>6</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>7</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>VM Network</rasd:Connection>
        <rasd:Description>VmxNet3 ethernet adapter on "VM Network"</rasd:Description>
        <rasd:ElementName>Ethernet 1</rasd:ElementName>
        <rasd:InstanceID>7</rasd:InstanceID>
        <rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
      <vmw:Config ovf:required="false" vmw:key="firmware" vmw:value="bios"/>
      <vmw:Config ovf:required="false" vmw:key="tools.syncTimeWithHost" vmw:value="false"/>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
EOF
	{
		printf 'SHA256(%s)= %s\n' "$NAME.ovf" "$(sha256 "$WORK/$NAME.ovf")"
		printf 'SHA256(%s)= %s\n' "$DISK" "$(sha256 "$WORK/$DISK")"
	} >"$WORK/$NAME.mf"
	# The descriptor must come first in an OVA, then the manifest.
	tar --format=ustar -cf "$OUT/$NAME.ova.tmp" -C "$WORK" "$NAME.ovf" "$NAME.mf" "$DISK"
	mv -f "$OUT/$NAME.ova.tmp" "$OUT/$NAME.ova"
	echo "convert.sh: wrote $OUT/$NAME.ova"
	;;
*)
	die "unknown format $FORMAT; want vhd or ova"
	;;
esac
