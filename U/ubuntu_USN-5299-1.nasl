#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5299-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158254);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2020-26147",
    "CVE-2020-26558",
    "CVE-2021-0129",
    "CVE-2021-3483",
    "CVE-2021-3564",
    "CVE-2021-3612",
    "CVE-2021-3679",
    "CVE-2021-28972",
    "CVE-2021-33034",
    "CVE-2021-34693",
    "CVE-2021-38204",
    "CVE-2021-42008",
    "CVE-2021-45485"
  );
  script_xref(name:"USN", value:"5299-1");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel vulnerabilities (USN-5299-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5299-1 advisory.

  - An issue was discovered in the Linux kernel 5.8.9. The WEP, WPA, WPA2, and WPA3 implementations reassemble
    fragments even though some of them were sent in plaintext. This vulnerability can be abused to inject
    packets and/or exfiltrate selected fragments when another device sends fragmented frames and the WEP,
    CCMP, or GCMP data-confidentiality protocol is used. (CVE-2020-26147)

  - Bluetooth LE and BR/EDR secure pairing in Bluetooth Core Specification 2.1 through 5.2 may permit a nearby
    man-in-the-middle attacker to identify the Passkey used during pairing (in the Passkey authentication
    procedure) by reflection of the public key and the authentication evidence of the initiating device,
    potentially permitting this attacker to complete authenticated pairing with the responding device using
    the correct Passkey for the pairing session. The attack methodology determines the Passkey value one bit
    at a time. (CVE-2020-26558)

  - Improper access control in BlueZ may allow an authenticated user to potentially enable information
    disclosure via adjacent access. (CVE-2021-0129)

  - A flaw was found in the Nosy driver in the Linux kernel. This issue allows a device to be inserted twice
    into a doubly-linked list, leading to a use-after-free when one of these devices is removed. The highest
    threat from this vulnerability is to confidentiality, integrity, as well as system availability. Versions
    before kernel 5.12-rc6 are affected (CVE-2021-3483)

  - A flaw double-free memory corruption in the Linux kernel HCI device initialization subsystem was found in
    the way user attach malicious HCI TTY Bluetooth device. A local user could use this flaw to crash the
    system. This flaw affects all the Linux kernel versions starting from 3.13. (CVE-2021-3564)

  - An out-of-bounds memory write flaw was found in the Linux kernel's joystick devices subsystem in versions
    before 5.9-rc1, in the way the user calls ioctl JSIOCSBTNMAP. This flaw allows a local user to crash the
    system or possibly escalate their privileges on the system. The highest threat from this vulnerability is
    to confidentiality, integrity, as well as system availability. (CVE-2021-3612)

  - A lack of CPU resource in the Linux kernel tracing module functionality in versions prior to 5.14-rc3 was
    found in the way user uses trace ring buffer in a specific way. Only privileged local users (with
    CAP_SYS_ADMIN capability) could use this flaw to starve the resources causing denial of service.
    (CVE-2021-3679)

  - In drivers/pci/hotplug/rpadlpar_sysfs.c in the Linux kernel through 5.11.8, the RPA PCI Hotplug driver has
    a user-tolerable buffer overflow when writing a new device name to the driver from userspace, allowing
    userspace to write data to the kernel stack frame directly. This occurs because add_slot_store and
    remove_slot_store mishandle drc_name '\0' termination, aka CID-cc7a0bb058b8. (CVE-2021-28972)

  - In the Linux kernel before 5.12.4, net/bluetooth/hci_event.c has a use-after-free when destroying an
    hci_chan, aka CID-5c4c8c954409. This leads to writing an arbitrary value. (CVE-2021-33034)

  - net/can/bcm.c in the Linux kernel through 5.12.10 allows local users to obtain sensitive information from
    kernel stack memory because parts of a data structure are uninitialized. (CVE-2021-34693)

  - drivers/usb/host/max3421-hcd.c in the Linux kernel before 5.13.6 allows physically proximate attackers to
    cause a denial of service (use-after-free and panic) by removing a MAX-3421 USB device in certain
    situations. (CVE-2021-38204)

  - The decode_data function in drivers/net/hamradio/6pack.c in the Linux kernel before 5.13.13 has a slab
    out-of-bounds write. Input from a process that has the CAP_NET_ADMIN capability can lead to root access.
    (CVE-2021-42008)

  - In the IPv6 implementation in the Linux kernel before 5.13.3, net/ipv6/output_core.c has an information
    leak because of certain use of a hash table which, although big, doesn't properly consider that IPv6-based
    attackers can typically choose among many IPv6 source addresses. (CVE-2021-45485)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5299-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3612");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-42008");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.4.0-1099");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.4.0-1135");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.4.0-1099");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.4.0-1135");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.4.0-1099");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.4.0-1135");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1099-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1100-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1135-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-219-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-219-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1099-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1100-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1135-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-219");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-219-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-219-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1099-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1100-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1135-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-219");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-219-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-219-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-generic-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-virtual-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1099-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1100-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1135-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-219-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-219-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-hwe-generic-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-hwe-virtual-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.4.0-219-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.4.0-219-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-cloud-tools-4.4.0-1100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-4.4.0-1100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-4.4.0-1100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lts-xenial-cloud-tools-4.4.0-219");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lts-xenial-tools-4.4.0-219");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1099-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1100-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1135-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-219-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-219-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.4.0-1135-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.4.0-219-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-4.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1099-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1100-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1135-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-219");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-219-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-219-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-xenial");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'linux-aws', 'pkgver': '4.4.0.1135.140'},
    {'osver': '16.04', 'pkgname': 'linux-aws-cloud-tools-4.4.0-1135', 'pkgver': '4.4.0-1135.149'},
    {'osver': '16.04', 'pkgname': 'linux-aws-headers-4.4.0-1135', 'pkgver': '4.4.0-1135.149'},
    {'osver': '16.04', 'pkgname': 'linux-aws-tools-4.4.0-1135', 'pkgver': '4.4.0-1135.149'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-1100-kvm', 'pkgver': '4.4.0-1100.109'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-1135-aws', 'pkgver': '4.4.0-1135.149'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-219-generic', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-219-lowlatency', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-1100-kvm', 'pkgver': '4.4.0-1100.109'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-1135-aws', 'pkgver': '4.4.0-1135.149'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-219', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-219-generic', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-219-lowlatency', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-crashdump', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-generic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-1100-kvm', 'pkgver': '4.4.0-1100.109'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-1135-aws', 'pkgver': '4.4.0-1135.149'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-219', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-219-generic', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-219-lowlatency', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-headers-aws', 'pkgver': '4.4.0.1135.140'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '4.4.0.1100.98'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-generic-trusty', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-virtual-trusty', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1100-kvm', 'pkgver': '4.4.0-1100.109'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1135-aws', 'pkgver': '4.4.0-1135.149'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-219-generic', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-219-lowlatency', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws', 'pkgver': '4.4.0.1135.140'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-hwe-generic-trusty', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-hwe-virtual-trusty', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.4.0.1100.98'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.4.0-219-generic', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.4.0-219-lowlatency', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-kvm', 'pkgver': '4.4.0.1100.98'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-cloud-tools-4.4.0-1100', 'pkgver': '4.4.0-1100.109'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-headers-4.4.0-1100', 'pkgver': '4.4.0-1100.109'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-tools-4.4.0-1100', 'pkgver': '4.4.0-1100.109'},
    {'osver': '16.04', 'pkgname': 'linux-libc-dev', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-1100-kvm', 'pkgver': '4.4.0-1100.109'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-1135-aws', 'pkgver': '4.4.0-1135.149'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-219-generic', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-219-lowlatency', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.4.0-1135-aws', 'pkgver': '4.4.0-1135.149'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.4.0-219-generic', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '4.4.0.1135.140'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-source', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-source-4.4.0', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-1100-kvm', 'pkgver': '4.4.0-1100.109'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-1135-aws', 'pkgver': '4.4.0-1135.149'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-219', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-219-generic', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-219-lowlatency', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-tools-aws', 'pkgver': '4.4.0.1135.140'},
    {'osver': '16.04', 'pkgname': 'linux-tools-common', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-host', 'pkgver': '4.4.0-219.252'},
    {'osver': '16.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '4.4.0.1100.98'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-xenial', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-virtual', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-utopic', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-vivid', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-wily', 'pkgver': '4.4.0.219.226'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-xenial', 'pkgver': '4.4.0.219.226'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-cloud-tools-4.4.0-1135 / etc');
}
