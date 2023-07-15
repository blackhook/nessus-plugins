#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5339-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159143);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-3506",
    "CVE-2021-43976",
    "CVE-2021-44733",
    "CVE-2021-45095",
    "CVE-2022-0435",
    "CVE-2022-0492"
  );
  script_xref(name:"USN", value:"5339-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS : Linux kernel vulnerabilities (USN-5339-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5339-1 advisory.

  - An out-of-bounds (OOB) memory access flaw was found in fs/f2fs/node.c in the f2fs module in the Linux
    kernel in versions before 5.12.0-rc4. A bounds check failure allows a local attacker to gain access to
    out-of-bounds memory leading to a system crash or a leak of internal kernel information. The highest
    threat from this vulnerability is to system availability. (CVE-2021-3506)

  - In the Linux kernel through 5.15.2, mwifiex_usb_recv in drivers/net/wireless/marvell/mwifiex/usb.c allows
    an attacker (who can connect a crafted USB device) to cause a denial of service (skb_over_panic).
    (CVE-2021-43976)

  - A use-after-free exists in drivers/tee/tee_shm.c in the TEE subsystem in the Linux kernel through 5.15.11.
    This occurs because of a race condition in tee_shm_get_from_id during an attempt to free a shared memory
    object. (CVE-2021-44733)

  - pep_sock_accept in net/phonet/pep.c in the Linux kernel through 5.15.8 has a refcount leak.
    (CVE-2021-45095)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5339-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0435");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.15.0-1124");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.15.0-1124");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe-cloud-tools-4.15.0-1124");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe-tools-4.15.0-1124");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.15.0-1124");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-cloud-tools-4.15.0-1134");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-headers-4.15.0-1134");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-tools-4.15.0-1134");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-4.15.0-1134");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-4.15.0-1134");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-4.15.0-1134");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1038-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1090-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1110-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1119-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1123-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1124-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1134-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-173-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-173-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-173-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-1124-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-1134-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-173");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-173-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-173-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-dell300x-headers-4.15.0-1038");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-dell300x-tools-4.15.0-1038");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-4.15-headers-4.15.0-1119");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-4.15-tools-4.15.0-1119");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1038-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1090-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1110-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1119-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1123-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1124-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1134-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-173");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-173-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-173-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-173-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-cloud-tools-4.15.0-173");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-tools-4.15.0-173");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1038-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1090-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1110-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1119-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1123-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1124-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1124-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1134-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-173-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-173-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-173-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1038-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1090-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1119-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1124-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1134-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-173-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-173-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-4.15.0-1110");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-4.15.0-1110");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1038-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1090-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1110-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1119-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1123-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1124-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1134-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-173-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-173-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-173-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1090-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1119-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1124-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1134-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-173-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-4.15.0-1090");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-4.15.0-1090");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-headers-4.15.0-1123");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-tools-4.15.0-1123");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-4.15.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1038-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1090-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1110-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1119-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1123-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1124-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1134-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-173");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-173-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-173-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-173-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-16.04-edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(14\.04|16\.04|18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-3506', 'CVE-2021-43976', 'CVE-2021-44733', 'CVE-2021-45095', 'CVE-2022-0435', 'CVE-2022-0492');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5339-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '14.04', 'pkgname': 'linux-azure', 'pkgver': '4.15.0.1134.107'},
    {'osver': '14.04', 'pkgname': 'linux-azure-cloud-tools-4.15.0-1134', 'pkgver': '4.15.0-1134.147~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-azure-headers-4.15.0-1134', 'pkgver': '4.15.0-1134.147~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-azure-tools-4.15.0-1134', 'pkgver': '4.15.0-1134.147~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-buildinfo-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-cloud-tools-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '4.15.0.1134.107'},
    {'osver': '14.04', 'pkgname': 'linux-headers-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-headers-azure', 'pkgver': '4.15.0.1134.107'},
    {'osver': '14.04', 'pkgname': 'linux-image-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-image-azure', 'pkgver': '4.15.0.1134.107'},
    {'osver': '14.04', 'pkgname': 'linux-image-unsigned-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-modules-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-modules-extra-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '4.15.0.1134.107'},
    {'osver': '14.04', 'pkgname': 'linux-signed-azure', 'pkgver': '4.15.0.1134.107'},
    {'osver': '14.04', 'pkgname': 'linux-signed-image-azure', 'pkgver': '4.15.0.1134.107'},
    {'osver': '14.04', 'pkgname': 'linux-tools-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147~14.04.1'},
    {'osver': '14.04', 'pkgname': 'linux-tools-azure', 'pkgver': '4.15.0.1134.107'},
    {'osver': '16.04', 'pkgname': 'linux-aws-edge', 'pkgver': '4.15.0.1124.114'},
    {'osver': '16.04', 'pkgname': 'linux-aws-headers-4.15.0-1124', 'pkgver': '4.15.0-1124.133~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe', 'pkgver': '4.15.0.1124.114'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe-cloud-tools-4.15.0-1124', 'pkgver': '4.15.0-1124.133~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe-tools-4.15.0-1124', 'pkgver': '4.15.0-1124.133~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-173-generic', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-173-generic', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-generic-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-173', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-173-generic', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-aws-hwe', 'pkgver': '4.15.0.1124.114'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-headers-oem', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '4.15.0.1090.78'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-cloud-tools-4.15.0-173', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-tools-4.15.0-173', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1124-aws-hwe', 'pkgver': '4.15.0-1124.133~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-173-generic', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws-hwe', 'pkgver': '4.15.0.1124.114'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-image-oem', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-image-oracle', 'pkgver': '4.15.0.1090.78'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-173-generic', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-173-generic', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-173-generic', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-aws-hwe', 'pkgver': '4.15.0.1124.114'},
    {'osver': '16.04', 'pkgname': 'linux-oem', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-oracle', 'pkgver': '4.15.0.1090.78'},
    {'osver': '16.04', 'pkgname': 'linux-oracle-headers-4.15.0-1090', 'pkgver': '4.15.0-1090.99~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-oracle-tools-4.15.0-1090', 'pkgver': '4.15.0-1090.99~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-oem', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-oracle', 'pkgver': '4.15.0.1090.78'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-signed-oem', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-signed-oracle', 'pkgver': '4.15.0.1090.78'},
    {'osver': '16.04', 'pkgname': 'linux-source-4.15.0', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-173-generic', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-aws-hwe', 'pkgver': '4.15.0.1124.114'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-tools-oem', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '4.15.0.1090.78'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-hwe-16.04', 'pkgver': '4.15.0.173.165'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.173.165'},
    {'osver': '18.04', 'pkgname': 'linux-aws-cloud-tools-4.15.0-1124', 'pkgver': '4.15.0-1124.133'},
    {'osver': '18.04', 'pkgname': 'linux-aws-headers-4.15.0-1124', 'pkgver': '4.15.0-1124.133'},
    {'osver': '18.04', 'pkgname': 'linux-aws-lts-18.04', 'pkgver': '4.15.0.1124.127'},
    {'osver': '18.04', 'pkgname': 'linux-aws-tools-4.15.0-1124', 'pkgver': '4.15.0-1124.133'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-cloud-tools-4.15.0-1134', 'pkgver': '4.15.0-1134.147'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-headers-4.15.0-1134', 'pkgver': '4.15.0-1134.147'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-tools-4.15.0-1134', 'pkgver': '4.15.0-1134.147'},
    {'osver': '18.04', 'pkgname': 'linux-azure-lts-18.04', 'pkgver': '4.15.0.1134.107'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1038-dell300x', 'pkgver': '4.15.0-1038.43'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1110-kvm', 'pkgver': '4.15.0-1110.113'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1119-gcp', 'pkgver': '4.15.0-1119.133'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1123-snapdragon', 'pkgver': '4.15.0-1123.132'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-173-generic', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-173-generic-lpae', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-173', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-173-generic', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure-lts-18.04', 'pkgver': '4.15.0.1134.107'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-crashdump', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-dell300x', 'pkgver': '4.15.0.1038.40'},
    {'osver': '18.04', 'pkgname': 'linux-dell300x-headers-4.15.0-1038', 'pkgver': '4.15.0-1038.43'},
    {'osver': '18.04', 'pkgname': 'linux-dell300x-tools-4.15.0-1038', 'pkgver': '4.15.0-1038.43'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-4.15-headers-4.15.0-1119', 'pkgver': '4.15.0-1119.133'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-4.15-tools-4.15.0-1119', 'pkgver': '4.15.0-1119.133'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-lts-18.04', 'pkgver': '4.15.0.1119.138'},
    {'osver': '18.04', 'pkgname': 'linux-generic', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1038-dell300x', 'pkgver': '4.15.0-1038.43'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1110-kvm', 'pkgver': '4.15.0-1110.113'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1119-gcp', 'pkgver': '4.15.0-1119.133'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1123-snapdragon', 'pkgver': '4.15.0-1123.132'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-173', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-173-generic', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-173-generic-lpae', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws-lts-18.04', 'pkgver': '4.15.0.1124.127'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure-lts-18.04', 'pkgver': '4.15.0.1134.107'},
    {'osver': '18.04', 'pkgname': 'linux-headers-dell300x', 'pkgver': '4.15.0.1038.40'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gcp-lts-18.04', 'pkgver': '4.15.0.1119.138'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '4.15.0.1110.106'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle-lts-18.04', 'pkgver': '4.15.0.1090.100'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon', 'pkgver': '4.15.0.1123.126'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1038-dell300x', 'pkgver': '4.15.0-1038.43'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1110-kvm', 'pkgver': '4.15.0-1110.113'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1119-gcp', 'pkgver': '4.15.0-1119.133'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1123-snapdragon', 'pkgver': '4.15.0-1123.132'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-173-generic', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-173-generic-lpae', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-lts-18.04', 'pkgver': '4.15.0.1124.127'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-lts-18.04', 'pkgver': '4.15.0.1134.107'},
    {'osver': '18.04', 'pkgname': 'linux-image-dell300x', 'pkgver': '4.15.0.1038.40'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-lts-18.04', 'pkgver': '4.15.0.1119.138'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.15.0.1110.106'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-lts-18.04', 'pkgver': '4.15.0.1090.100'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon', 'pkgver': '4.15.0.1123.126'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1038-dell300x', 'pkgver': '4.15.0-1038.43'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1119-gcp', 'pkgver': '4.15.0-1119.133'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-173-generic', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-kvm', 'pkgver': '4.15.0.1110.106'},
    {'osver': '18.04', 'pkgname': 'linux-kvm-headers-4.15.0-1110', 'pkgver': '4.15.0-1110.113'},
    {'osver': '18.04', 'pkgname': 'linux-kvm-tools-4.15.0-1110', 'pkgver': '4.15.0-1110.113'},
    {'osver': '18.04', 'pkgname': 'linux-libc-dev', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1038-dell300x', 'pkgver': '4.15.0-1038.43'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1110-kvm', 'pkgver': '4.15.0-1110.113'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1119-gcp', 'pkgver': '4.15.0-1119.133'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1123-snapdragon', 'pkgver': '4.15.0-1123.132'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-173-generic', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-173-generic-lpae', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1119-gcp', 'pkgver': '4.15.0-1119.133'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-173-generic', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws-lts-18.04', 'pkgver': '4.15.0.1124.127'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure-lts-18.04', 'pkgver': '4.15.0.1134.107'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gcp-lts-18.04', 'pkgver': '4.15.0.1119.138'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-headers-4.15.0-1090', 'pkgver': '4.15.0-1090.99'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-lts-18.04', 'pkgver': '4.15.0.1090.100'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-tools-4.15.0-1090', 'pkgver': '4.15.0-1090.99'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure-lts-18.04', 'pkgver': '4.15.0.1134.107'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure-lts-18.04', 'pkgver': '4.15.0.1134.107'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle-lts-18.04', 'pkgver': '4.15.0.1090.100'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle-lts-18.04', 'pkgver': '4.15.0.1090.100'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon', 'pkgver': '4.15.0.1123.126'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-headers-4.15.0-1123', 'pkgver': '4.15.0-1123.132'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-tools-4.15.0-1123', 'pkgver': '4.15.0-1123.132'},
    {'osver': '18.04', 'pkgname': 'linux-source', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-source-4.15.0', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1038-dell300x', 'pkgver': '4.15.0-1038.43'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1090-oracle', 'pkgver': '4.15.0-1090.99'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1110-kvm', 'pkgver': '4.15.0-1110.113'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1119-gcp', 'pkgver': '4.15.0-1119.133'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1123-snapdragon', 'pkgver': '4.15.0-1123.132'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1124-aws', 'pkgver': '4.15.0-1124.133'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1134-azure', 'pkgver': '4.15.0-1134.147'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-173', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-173-generic', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-173-generic-lpae', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-173-lowlatency', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws-lts-18.04', 'pkgver': '4.15.0.1124.127'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure-lts-18.04', 'pkgver': '4.15.0.1134.107'},
    {'osver': '18.04', 'pkgname': 'linux-tools-common', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-tools-dell300x', 'pkgver': '4.15.0.1038.40'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gcp-lts-18.04', 'pkgver': '4.15.0.1119.138'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-tools-host', 'pkgver': '4.15.0-173.182'},
    {'osver': '18.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '4.15.0.1110.106'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle-lts-18.04', 'pkgver': '4.15.0.1090.100'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon', 'pkgver': '4.15.0.1123.126'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-virtual', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-16.04', 'pkgver': '4.15.0.173.162'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.173.162'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws-cloud-tools-4.15.0-1124 / linux-aws-edge / etc');
}
