#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5209-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156484);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-3760",
    "CVE-2021-4002",
    "CVE-2021-20317",
    "CVE-2021-20321",
    "CVE-2021-41864",
    "CVE-2021-43389"
  );
  script_xref(name:"USN", value:"5209-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Linux kernel vulnerabilities (USN-5209-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5209-1 advisory.

  - prealloc_elems_and_freelist in kernel/bpf/stackmap.c in the Linux kernel before 5.14.12 allows
    unprivileged users to trigger an eBPF multiplication integer overflow with a resultant out-of-bounds
    write. (CVE-2021-41864)

  - A flaw was found in the Linux kernel. A use-after-free vulnerability in the NFC stack can lead to a threat
    to confidentiality, integrity, and system availability. (CVE-2021-3760)

  - A flaw was found in the Linux kernel. A corrupted timer tree caused the task wakeup to be missing in the
    timerqueue_add function in lib/timerqueue.c. This flaw allows a local attacker with special user
    privileges to cause a denial of service, slowing and eventually stopping the system while running OSP.
    (CVE-2021-20317)

  - A race condition accessing file object in the Linux kernel OverlayFS subsystem was found in the way users
    do rename in specific way with OverlayFS. A local user could use this flaw to crash the system.
    (CVE-2021-20321)

  - An issue was discovered in the Linux kernel before 5.14.15. There is an array-index-out-of-bounds flaw in
    the detach_capi_ctr function in drivers/isdn/capi/kcapi.c. (CVE-2021-43389)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5209-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.15.0-1118");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.15.0-1118");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe-cloud-tools-4.15.0-1118");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe-tools-4.15.0-1118");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.15.0-1118");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-cloud-tools-4.15.0-1129");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-headers-4.15.0-1129");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-tools-4.15.0-1129");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-4.15.0-1129");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-4.15.0-1129");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-4.15.0-1129");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1033-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1085-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1101-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1105-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1114-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1118-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1118-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1129-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-166-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-166-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-166-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-1118-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-1129-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-166");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-166-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-166-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-edge");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-dell300x-headers-4.15.0-1033");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-dell300x-tools-4.15.0-1033");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-4.15-headers-4.15.0-1114");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-4.15-tools-4.15.0-1114");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-4.15.0-1114");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-4.15.0-1114");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1033-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1085-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1101-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1105-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1114-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1118-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1118-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1129-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-166");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-166-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-166-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-166-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-cloud-tools-4.15.0-166");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-tools-4.15.0-166");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1033-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1085-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1101-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1105-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1114-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1118-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1118-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1129-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-166-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-166-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-166-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1033-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1085-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1114-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1129-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-166-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-166-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-4.15.0-1105");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-4.15.0-1105");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1033-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1085-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1101-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1105-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1114-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1118-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1118-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1129-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-166-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-166-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-166-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1085-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1114-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1118-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1129-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-166-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-4.15.0-1085");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-4.15.0-1085");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-headers-4.15.0-1101");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-tools-4.15.0-1101");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure-edge");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-headers-4.15.0-1118");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-tools-4.15.0-1118");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-4.15.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1033-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1085-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1101-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1105-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1114-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1118-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1118-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1129-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-166");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-166-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-166-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-166-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-dell300x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi2");
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
if (! preg(pattern:"^(16\.04|18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-3760', 'CVE-2021-4002', 'CVE-2021-20317', 'CVE-2021-20321', 'CVE-2021-41864', 'CVE-2021-43389');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5209-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '16.04', 'pkgname': 'linux-aws-edge', 'pkgver': '4.15.0.1118.108'},
    {'osver': '16.04', 'pkgname': 'linux-aws-headers-4.15.0-1118', 'pkgver': '4.15.0-1118.125~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe', 'pkgver': '4.15.0.1118.108'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe-cloud-tools-4.15.0-1118', 'pkgver': '4.15.0-1118.125~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe-tools-4.15.0-1118', 'pkgver': '4.15.0-1118.125~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-azure', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-azure-cloud-tools-4.15.0-1129', 'pkgver': '4.15.0-1129.142~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-azure-edge', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-azure-headers-4.15.0-1129', 'pkgver': '4.15.0-1129.142~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-azure-tools-4.15.0-1129', 'pkgver': '4.15.0-1129.142~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-166-generic', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-166-generic', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-azure-edge', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-gcp', 'pkgver': '4.15.0.1114.115'},
    {'osver': '16.04', 'pkgname': 'linux-gcp-headers-4.15.0-1114', 'pkgver': '4.15.0-1114.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-gcp-tools-4.15.0-1114', 'pkgver': '4.15.0-1114.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-generic-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-gke', 'pkgver': '4.15.0.1114.115'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-166', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-166-generic', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-aws-hwe', 'pkgver': '4.15.0.1118.108'},
    {'osver': '16.04', 'pkgname': 'linux-headers-azure', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-headers-azure-edge', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '4.15.0.1114.115'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-headers-gke', 'pkgver': '4.15.0.1114.115'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-headers-oem', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '4.15.0.1085.73'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-cloud-tools-4.15.0-166', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-tools-4.15.0-166', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-166-generic', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws-hwe', 'pkgver': '4.15.0.1118.108'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-image-gcp', 'pkgver': '4.15.0.1114.115'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-image-gke', 'pkgver': '4.15.0.1114.115'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-image-oem', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-image-oracle', 'pkgver': '4.15.0.1085.73'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-166-generic', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-166-generic', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-166-generic', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-aws-hwe', 'pkgver': '4.15.0.1118.108'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-azure-edge', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '4.15.0.1114.115'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '4.15.0.1114.115'},
    {'osver': '16.04', 'pkgname': 'linux-oem', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-oracle', 'pkgver': '4.15.0.1085.73'},
    {'osver': '16.04', 'pkgname': 'linux-oracle-headers-4.15.0-1085', 'pkgver': '4.15.0-1085.93~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-oracle-tools-4.15.0-1085', 'pkgver': '4.15.0-1085.93~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-signed-azure', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-signed-azure-edge', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-azure', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-azure-edge', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-oem', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-oracle', 'pkgver': '4.15.0.1085.73'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-signed-oem', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-signed-oracle', 'pkgver': '4.15.0.1085.73'},
    {'osver': '16.04', 'pkgname': 'linux-source-4.15.0', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-166-generic', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-aws-hwe', 'pkgver': '4.15.0.1118.108'},
    {'osver': '16.04', 'pkgname': 'linux-tools-azure', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-tools-azure-edge', 'pkgver': '4.15.0.1129.120'},
    {'osver': '16.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '4.15.0.1114.115'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-tools-gke', 'pkgver': '4.15.0.1114.115'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-tools-oem', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '4.15.0.1085.73'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-hwe-16.04', 'pkgver': '4.15.0.166.158'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.166.158'},
    {'osver': '18.04', 'pkgname': 'linux-aws-cloud-tools-4.15.0-1118', 'pkgver': '4.15.0-1118.125'},
    {'osver': '18.04', 'pkgname': 'linux-aws-headers-4.15.0-1118', 'pkgver': '4.15.0-1118.125'},
    {'osver': '18.04', 'pkgname': 'linux-aws-lts-18.04', 'pkgver': '4.15.0.1118.121'},
    {'osver': '18.04', 'pkgname': 'linux-aws-tools-4.15.0-1118', 'pkgver': '4.15.0-1118.125'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-cloud-tools-4.15.0-1129', 'pkgver': '4.15.0-1129.142'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-headers-4.15.0-1129', 'pkgver': '4.15.0-1129.142'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-tools-4.15.0-1129', 'pkgver': '4.15.0-1129.142'},
    {'osver': '18.04', 'pkgname': 'linux-azure-lts-18.04', 'pkgver': '4.15.0.1129.102'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1033-dell300x', 'pkgver': '4.15.0-1033.38'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1101-raspi2', 'pkgver': '4.15.0-1101.108'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1105-kvm', 'pkgver': '4.15.0-1105.107'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1118-snapdragon', 'pkgver': '4.15.0-1118.127'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-166-generic', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-166-generic-lpae', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-166', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-166-generic', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure-lts-18.04', 'pkgver': '4.15.0.1129.102'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-crashdump', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-dell300x', 'pkgver': '4.15.0.1033.35'},
    {'osver': '18.04', 'pkgname': 'linux-dell300x-headers-4.15.0-1033', 'pkgver': '4.15.0-1033.38'},
    {'osver': '18.04', 'pkgname': 'linux-dell300x-tools-4.15.0-1033', 'pkgver': '4.15.0-1033.38'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-4.15-headers-4.15.0-1114', 'pkgver': '4.15.0-1114.128'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-4.15-tools-4.15.0-1114', 'pkgver': '4.15.0-1114.128'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-lts-18.04', 'pkgver': '4.15.0.1114.133'},
    {'osver': '18.04', 'pkgname': 'linux-generic', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1033-dell300x', 'pkgver': '4.15.0-1033.38'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1101-raspi2', 'pkgver': '4.15.0-1101.108'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1105-kvm', 'pkgver': '4.15.0-1105.107'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1118-snapdragon', 'pkgver': '4.15.0-1118.127'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-166', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-166-generic', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-166-generic-lpae', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws-lts-18.04', 'pkgver': '4.15.0.1118.121'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure-lts-18.04', 'pkgver': '4.15.0.1129.102'},
    {'osver': '18.04', 'pkgname': 'linux-headers-dell300x', 'pkgver': '4.15.0.1033.35'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gcp-lts-18.04', 'pkgver': '4.15.0.1114.133'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '4.15.0.1105.101'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle-lts-18.04', 'pkgver': '4.15.0.1085.95'},
    {'osver': '18.04', 'pkgname': 'linux-headers-raspi2', 'pkgver': '4.15.0.1101.99'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon', 'pkgver': '4.15.0.1118.121'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1033-dell300x', 'pkgver': '4.15.0-1033.38'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1101-raspi2', 'pkgver': '4.15.0-1101.108'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1105-kvm', 'pkgver': '4.15.0-1105.107'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1118-snapdragon', 'pkgver': '4.15.0-1118.127'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-166-generic', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-166-generic-lpae', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-lts-18.04', 'pkgver': '4.15.0.1118.121'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-lts-18.04', 'pkgver': '4.15.0.1129.102'},
    {'osver': '18.04', 'pkgname': 'linux-image-dell300x', 'pkgver': '4.15.0.1033.35'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-lts-18.04', 'pkgver': '4.15.0.1114.133'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.15.0.1105.101'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-lts-18.04', 'pkgver': '4.15.0.1085.95'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi2', 'pkgver': '4.15.0.1101.99'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon', 'pkgver': '4.15.0.1118.121'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1033-dell300x', 'pkgver': '4.15.0-1033.38'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-166-generic', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-kvm', 'pkgver': '4.15.0.1105.101'},
    {'osver': '18.04', 'pkgname': 'linux-kvm-headers-4.15.0-1105', 'pkgver': '4.15.0-1105.107'},
    {'osver': '18.04', 'pkgname': 'linux-kvm-tools-4.15.0-1105', 'pkgver': '4.15.0-1105.107'},
    {'osver': '18.04', 'pkgname': 'linux-libc-dev', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1033-dell300x', 'pkgver': '4.15.0-1033.38'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1101-raspi2', 'pkgver': '4.15.0-1101.108'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1105-kvm', 'pkgver': '4.15.0-1105.107'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1118-snapdragon', 'pkgver': '4.15.0-1118.127'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-166-generic', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-166-generic-lpae', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-166-generic', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws-lts-18.04', 'pkgver': '4.15.0.1118.121'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure-lts-18.04', 'pkgver': '4.15.0.1129.102'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gcp-lts-18.04', 'pkgver': '4.15.0.1114.133'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-headers-4.15.0-1085', 'pkgver': '4.15.0-1085.93'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-lts-18.04', 'pkgver': '4.15.0.1085.95'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-tools-4.15.0-1085', 'pkgver': '4.15.0-1085.93'},
    {'osver': '18.04', 'pkgname': 'linux-raspi2', 'pkgver': '4.15.0.1101.99'},
    {'osver': '18.04', 'pkgname': 'linux-raspi2-headers-4.15.0-1101', 'pkgver': '4.15.0-1101.108'},
    {'osver': '18.04', 'pkgname': 'linux-raspi2-tools-4.15.0-1101', 'pkgver': '4.15.0-1101.108'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure-lts-18.04', 'pkgver': '4.15.0.1129.102'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure-lts-18.04', 'pkgver': '4.15.0.1129.102'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle-lts-18.04', 'pkgver': '4.15.0.1085.95'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle-lts-18.04', 'pkgver': '4.15.0.1085.95'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon', 'pkgver': '4.15.0.1118.121'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-headers-4.15.0-1118', 'pkgver': '4.15.0-1118.127'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-tools-4.15.0-1118', 'pkgver': '4.15.0-1118.127'},
    {'osver': '18.04', 'pkgname': 'linux-source', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-source-4.15.0', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1033-dell300x', 'pkgver': '4.15.0-1033.38'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1085-oracle', 'pkgver': '4.15.0-1085.93'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1101-raspi2', 'pkgver': '4.15.0-1101.108'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1105-kvm', 'pkgver': '4.15.0-1105.107'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1114-gcp', 'pkgver': '4.15.0-1114.128'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1118-aws', 'pkgver': '4.15.0-1118.125'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1118-snapdragon', 'pkgver': '4.15.0-1118.127'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1129-azure', 'pkgver': '4.15.0-1129.142'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-166', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-166-generic', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-166-generic-lpae', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-166-lowlatency', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws-lts-18.04', 'pkgver': '4.15.0.1118.121'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure-lts-18.04', 'pkgver': '4.15.0.1129.102'},
    {'osver': '18.04', 'pkgname': 'linux-tools-common', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-tools-dell300x', 'pkgver': '4.15.0.1033.35'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gcp-lts-18.04', 'pkgver': '4.15.0.1114.133'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-tools-host', 'pkgver': '4.15.0-166.174'},
    {'osver': '18.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '4.15.0.1105.101'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle-lts-18.04', 'pkgver': '4.15.0.1085.95'},
    {'osver': '18.04', 'pkgname': 'linux-tools-raspi2', 'pkgver': '4.15.0.1101.99'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon', 'pkgver': '4.15.0.1118.121'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-virtual', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-16.04', 'pkgver': '4.15.0.166.155'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.166.155'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws-cloud-tools-4.15.0-1118 / linux-aws-edge / etc');
}
