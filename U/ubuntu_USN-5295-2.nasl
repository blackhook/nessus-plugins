#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5295-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158256);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-4083",
    "CVE-2021-4155",
    "CVE-2021-22600",
    "CVE-2022-0330",
    "CVE-2022-22942"
  );
  script_xref(name:"USN", value:"5295-2");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/02");

  script_name(english:"Ubuntu 21.10 : Linux kernel vulnerabilities (USN-5295-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 21.10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
USN-5295-2 advisory.

  - A double free bug in packet_set_ring() in net/packet/af_packet.c can be exploited by a local user through
    crafted syscalls to escalate privileges or deny service. We recommend upgrading kernel past the effected
    versions or rebuilding past ec6af094ea28f0f2dda1a6a33b14cd57e36a9755 (CVE-2021-22600)

  - A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges on the system.
    This flaw affects Linux kernel versions prior to 5.16-rc4. (CVE-2021-4083)

  - A data leak flaw was found in the way XFS_IOC_ALLOCSP IOCTL in the XFS filesystem allowed for size
    increase of files with unaligned size. A local attacker could use this flaw to leak data on the XFS
    filesystem otherwise not accessible to them. (CVE-2021-4155)

  - A random memory access flaw was found in the Linux kernel's GPU i915 kernel driver functionality in the
    way a user may run malicious code on the GPU. This flaw allows a local user to crash the system or
    escalate their privileges on the system. (CVE-2022-0330)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5295-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22600");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0330");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-5.13.0-1014");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-5.13.0-1014");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-5.13.0-1014");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1013-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1015-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1017-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1017-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1018-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-30-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-30-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-30-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-30-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-30-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-30-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-5.13.0-1015");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-5.13.0-1015");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1013-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1015-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1017-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1017-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1018-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-30-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-30-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-30-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-30-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1013-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1015-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1017-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1017-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1018-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-30-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-30-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-30-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-30-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1013-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1015-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1018-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-30-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-30-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-30-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-5.13.0-1013");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-5.13.0-1013");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1013-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1015-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1017-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1017-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1018-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-30-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-30-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-30-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-30-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1015-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1017-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1017-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1018-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-30-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-5.13.0-1018");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-5.13.0-1018");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-headers-5.13.0-1017");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-tools-5.13.0-1017");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.13.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1013-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1015-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1017-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1017-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1018-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-30-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-30-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-30-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-30-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-20.04-edge");
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
if (! ('21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '21.10', 'pkgname': 'linux-aws', 'pkgver': '5.13.0.1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-aws-cloud-tools-5.13.0-1014', 'pkgver': '5.13.0-1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-aws-headers-5.13.0-1014', 'pkgver': '5.13.0-1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-aws-tools-5.13.0-1014', 'pkgver': '5.13.0-1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-azure', 'pkgver': '5.13.0.1014.14'},
    {'osver': '21.10', 'pkgname': 'linux-azure-cloud-tools-5.13.0-1014', 'pkgver': '5.13.0-1014.16'},
    {'osver': '21.10', 'pkgname': 'linux-azure-headers-5.13.0-1014', 'pkgver': '5.13.0-1014.16'},
    {'osver': '21.10', 'pkgname': 'linux-azure-tools-5.13.0-1014', 'pkgver': '5.13.0-1014.16'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1013-kvm', 'pkgver': '5.13.0-1013.14'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1014-aws', 'pkgver': '5.13.0-1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1014-azure', 'pkgver': '5.13.0-1014.16'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1015-gcp', 'pkgver': '5.13.0-1015.18'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1017-raspi', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1017-raspi-nolpae', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1018-oracle', 'pkgver': '5.13.0-1018.22'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-30-generic', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-30-generic-64k', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-30-generic-lpae', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-30-lowlatency', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-1014-aws', 'pkgver': '5.13.0-1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-1014-azure', 'pkgver': '5.13.0-1014.16'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-30', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-30-generic', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-30-lowlatency', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.13.0.1014.14'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-crashdump', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-gcp', 'pkgver': '5.13.0.1015.14'},
    {'osver': '21.10', 'pkgname': 'linux-gcp-headers-5.13.0-1015', 'pkgver': '5.13.0-1015.18'},
    {'osver': '21.10', 'pkgname': 'linux-gcp-tools-5.13.0-1015', 'pkgver': '5.13.0-1015.18'},
    {'osver': '21.10', 'pkgname': 'linux-generic', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-generic-64k', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-generic-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-gke', 'pkgver': '5.13.0.1015.14'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1013-kvm', 'pkgver': '5.13.0-1013.14'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1014-aws', 'pkgver': '5.13.0-1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1014-azure', 'pkgver': '5.13.0-1014.16'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1015-gcp', 'pkgver': '5.13.0-1015.18'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1017-raspi', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1017-raspi-nolpae', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1018-oracle', 'pkgver': '5.13.0-1018.22'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-30', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-30-generic', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-30-generic-64k', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-30-generic-lpae', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-30-lowlatency', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-headers-aws', 'pkgver': '5.13.0.1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-headers-azure', 'pkgver': '5.13.0.1014.14'},
    {'osver': '21.10', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.13.0.1015.14'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-64k', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-gke', 'pkgver': '5.13.0.1015.14'},
    {'osver': '21.10', 'pkgname': 'linux-headers-kvm', 'pkgver': '5.13.0.1013.13'},
    {'osver': '21.10', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-oem-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.13.0.1018.18'},
    {'osver': '21.10', 'pkgname': 'linux-headers-raspi', 'pkgver': '5.13.0.1017.22'},
    {'osver': '21.10', 'pkgname': 'linux-headers-raspi-nolpae', 'pkgver': '5.13.0.1017.22'},
    {'osver': '21.10', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-headers-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1013-kvm', 'pkgver': '5.13.0-1013.14'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1014-azure', 'pkgver': '5.13.0-1014.16'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1015-gcp', 'pkgver': '5.13.0-1015.18'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1017-raspi', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1017-raspi-nolpae', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1018-oracle', 'pkgver': '5.13.0-1018.22'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-30-generic', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-30-generic-64k', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-30-generic-lpae', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-30-lowlatency', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-image-aws', 'pkgver': '5.13.0.1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-image-azure', 'pkgver': '5.13.0.1014.14'},
    {'osver': '21.10', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-extra-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-gcp', 'pkgver': '5.13.0.1015.14'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-gke', 'pkgver': '5.13.0.1015.14'},
    {'osver': '21.10', 'pkgname': 'linux-image-kvm', 'pkgver': '5.13.0.1013.13'},
    {'osver': '21.10', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-oracle', 'pkgver': '5.13.0.1018.18'},
    {'osver': '21.10', 'pkgname': 'linux-image-raspi', 'pkgver': '5.13.0.1017.22'},
    {'osver': '21.10', 'pkgname': 'linux-image-raspi-nolpae', 'pkgver': '5.13.0.1017.22'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1013-kvm', 'pkgver': '5.13.0-1013.14'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1014-aws', 'pkgver': '5.13.0-1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1014-azure', 'pkgver': '5.13.0-1014.16'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1015-gcp', 'pkgver': '5.13.0-1015.18'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1018-oracle', 'pkgver': '5.13.0-1018.22'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-30-generic', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-30-generic-64k', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-30-lowlatency', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-image-virtual', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-kvm', 'pkgver': '5.13.0.1013.13'},
    {'osver': '21.10', 'pkgname': 'linux-kvm-headers-5.13.0-1013', 'pkgver': '5.13.0-1013.14'},
    {'osver': '21.10', 'pkgname': 'linux-kvm-tools-5.13.0-1013', 'pkgver': '5.13.0-1013.14'},
    {'osver': '21.10', 'pkgname': 'linux-libc-dev', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-lowlatency', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1013-kvm', 'pkgver': '5.13.0-1013.14'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1014-aws', 'pkgver': '5.13.0-1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1014-azure', 'pkgver': '5.13.0-1014.16'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1015-gcp', 'pkgver': '5.13.0-1015.18'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1017-raspi', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1017-raspi-nolpae', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1018-oracle', 'pkgver': '5.13.0-1018.22'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-30-generic', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-30-generic-64k', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-30-generic-lpae', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-30-lowlatency', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1014-aws', 'pkgver': '5.13.0-1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1014-azure', 'pkgver': '5.13.0-1014.16'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1015-gcp', 'pkgver': '5.13.0-1015.18'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1017-raspi', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1017-raspi-nolpae', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1018-oracle', 'pkgver': '5.13.0-1018.22'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-30-generic', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.13.0.1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.13.0.1014.14'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.13.0.1015.14'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '5.13.0.1015.14'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-raspi', 'pkgver': '5.13.0.1017.22'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-raspi-nolpae', 'pkgver': '5.13.0.1017.22'},
    {'osver': '21.10', 'pkgname': 'linux-oem-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-oracle', 'pkgver': '5.13.0.1018.18'},
    {'osver': '21.10', 'pkgname': 'linux-oracle-headers-5.13.0-1018', 'pkgver': '5.13.0-1018.22'},
    {'osver': '21.10', 'pkgname': 'linux-oracle-tools-5.13.0-1018', 'pkgver': '5.13.0-1018.22'},
    {'osver': '21.10', 'pkgname': 'linux-raspi', 'pkgver': '5.13.0.1017.22'},
    {'osver': '21.10', 'pkgname': 'linux-raspi-headers-5.13.0-1017', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-raspi-nolpae', 'pkgver': '5.13.0.1017.22'},
    {'osver': '21.10', 'pkgname': 'linux-raspi-tools-5.13.0-1017', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-source', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-source-5.13.0', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1013-kvm', 'pkgver': '5.13.0-1013.14'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1014-aws', 'pkgver': '5.13.0-1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1014-azure', 'pkgver': '5.13.0-1014.16'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1015-gcp', 'pkgver': '5.13.0-1015.18'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1017-raspi', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1017-raspi-nolpae', 'pkgver': '5.13.0-1017.19'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1018-oracle', 'pkgver': '5.13.0-1018.22'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-30', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-30-generic', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-30-generic-64k', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-30-generic-lpae', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-30-lowlatency', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-tools-aws', 'pkgver': '5.13.0.1014.15'},
    {'osver': '21.10', 'pkgname': 'linux-tools-azure', 'pkgver': '5.13.0.1014.14'},
    {'osver': '21.10', 'pkgname': 'linux-tools-common', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.13.0.1015.14'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-64k', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-gke', 'pkgver': '5.13.0.1015.14'},
    {'osver': '21.10', 'pkgname': 'linux-tools-host', 'pkgver': '5.13.0-30.33'},
    {'osver': '21.10', 'pkgname': 'linux-tools-kvm', 'pkgver': '5.13.0.1013.13'},
    {'osver': '21.10', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-oem-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.13.0.1018.18'},
    {'osver': '21.10', 'pkgname': 'linux-tools-raspi', 'pkgver': '5.13.0.1017.22'},
    {'osver': '21.10', 'pkgname': 'linux-tools-raspi-nolpae', 'pkgver': '5.13.0.1017.22'},
    {'osver': '21.10', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-tools-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-virtual', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.13.0.30.40'},
    {'osver': '21.10', 'pkgname': 'linux-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.30.40'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-cloud-tools-5.13.0-1014 / etc');
}
