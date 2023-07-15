#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5045-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152639);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-3564", "CVE-2021-3573", "CVE-2021-34693");
  script_xref(name:"USN", value:"5045-1");

  script_name(english:"Ubuntu 18.04 LTS : Linux kernel vulnerabilities (USN-5045-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5045-1 advisory.

  - A flaw double-free memory corruption in the Linux kernel HCI device initialization subsystem was found in
    the way user attach malicious HCI TTY Bluetooth device. A local user could use this flaw to crash the
    system. This flaw affects all the Linux kernel versions starting from 3.13. (CVE-2021-3564)

  - A use-after-free in function hci_sock_bound_ioctl() of the Linux kernel HCI subsystem was found in the way
    user calls ioct HCIUNBLOCKADDR or other way triggers race condition of the call hci_unregister_dev()
    together with one of the calls hci_sock_blacklist_add(), hci_sock_blacklist_del(), hci_get_conn_info(),
    hci_get_auth_info(). A privileged local user could use this flaw to crash the system or escalate their
    privileges on the system. This flaw affects the Linux kernel versions prior to 5.13-rc5. (CVE-2021-3573)

  - net/can/bcm.c in the Linux kernel through 5.12.10 allows local users to obtain sensitive information from
    kernel stack memory because parts of a data structure are uninitialized. (CVE-2021-34693)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5045-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3573");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-cloud-tools-5.4.0-1055");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-headers-5.4.0-1055");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-tools-5.4.0-1055");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-cloud-tools-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-headers-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-tools-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1022-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1051-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1051-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1053-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1055-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1056-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-81-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-81-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-81-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1022-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1055-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1056-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-81-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-81-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.4-headers-5.4.0-1051");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.4-tools-5.4.0-1051");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.4-headers-5.4.0-1051");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.4-tools-5.4.0-1051");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-cloud-tools-5.4.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-headers-5.4.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-tools-5.4.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1022-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1051-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1051-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1053-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1055-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1056-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-81-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-81-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-81-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-cloud-tools-5.4.0-81");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-headers-5.4.0-81");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-tools-5.4.0-81");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1022-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1051-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1051-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1053-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1055-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1056-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-81-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-81-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-81-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1022-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1051-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1051-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1053-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1056-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-81-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-81-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1022-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1051-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1051-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1053-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1055-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1056-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-81-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-81-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-81-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1022-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1051-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1051-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1053-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1055-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1056-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-81-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-headers-5.4.0-1053");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-tools-5.4.0-1053");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1022-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1051-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1051-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1053-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1055-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1056-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-81-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-81-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-81-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-18.04-edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3587', 'CVE-2021-34693');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5045-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '18.04', 'pkgname': 'linux-aws', 'pkgver': '5.4.0.1055.38'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-cloud-tools-5.4.0-1055', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-headers-5.4.0-1055', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-tools-5.4.0-1055', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-aws-edge', 'pkgver': '5.4.0.1055.38'},
    {'osver': '18.04', 'pkgname': 'linux-azure', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-cloud-tools-5.4.0-1056', 'pkgver': '5.4.0-1056.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-headers-5.4.0-1056', 'pkgver': '5.4.0-1056.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-tools-5.4.0-1056', 'pkgver': '5.4.0-1056.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-edge', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1022-gkeop', 'pkgver': '5.4.0-1022.23~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1051-gcp', 'pkgver': '5.4.0-1051.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1051-gke', 'pkgver': '5.4.0-1051.54~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1053-oracle', 'pkgver': '5.4.0-1053.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1055-aws', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1056-azure', 'pkgver': '5.4.0-1056.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-81-generic', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-81-generic-lpae', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-81-lowlatency', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1022-gkeop', 'pkgver': '5.4.0-1022.23~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1055-aws', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1056-azure', 'pkgver': '5.4.0-1056.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-81-generic', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-81-lowlatency', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure-edge', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-gkeop-5.4', 'pkgver': '5.4.0.1022.23~18.04.23'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-gcp', 'pkgver': '5.4.0.1051.37'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-5.4-headers-5.4.0-1051', 'pkgver': '5.4.0-1051.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-5.4-tools-5.4.0-1051', 'pkgver': '5.4.0-1051.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-edge', 'pkgver': '5.4.0.1051.37'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4', 'pkgver': '5.4.0.1051.54~18.04.16'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4-headers-5.4.0-1051', 'pkgver': '5.4.0-1051.54~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4-tools-5.4.0-1051', 'pkgver': '5.4.0-1051.54~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4', 'pkgver': '5.4.0.1022.23~18.04.23'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-cloud-tools-5.4.0-1022', 'pkgver': '5.4.0-1022.23~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-headers-5.4.0-1022', 'pkgver': '5.4.0-1022.23~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-source-5.4.0', 'pkgver': '5.4.0-1022.23~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-tools-5.4.0-1022', 'pkgver': '5.4.0-1022.23~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1022-gkeop', 'pkgver': '5.4.0-1022.23~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1051-gcp', 'pkgver': '5.4.0-1051.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1051-gke', 'pkgver': '5.4.0-1051.54~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1053-oracle', 'pkgver': '5.4.0-1053.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1055-aws', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1056-azure', 'pkgver': '5.4.0-1056.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-81-generic', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-81-generic-lpae', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-81-lowlatency', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws', 'pkgver': '5.4.0.1055.38'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws-edge', 'pkgver': '5.4.0.1055.38'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure-edge', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.4.0.1051.37'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gcp-edge', 'pkgver': '5.4.0.1051.37'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gke-5.4', 'pkgver': '5.4.0.1051.54~18.04.16'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gkeop-5.4', 'pkgver': '5.4.0.1022.23~18.04.23'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oem', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oem-osp1', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle-edge', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-cloud-tools-5.4.0-81', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-cloud-tools-common', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-headers-5.4.0-81', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-source-5.4.0', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-tools-5.4.0-81', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-tools-common', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1022-gkeop', 'pkgver': '5.4.0-1022.23~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1051-gcp', 'pkgver': '5.4.0-1051.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1051-gke', 'pkgver': '5.4.0-1051.54~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1053-oracle', 'pkgver': '5.4.0-1053.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1055-aws', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1056-azure', 'pkgver': '5.4.0-1056.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-81-generic', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-81-generic-lpae', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-81-lowlatency', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.4.0.1055.38'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-edge', 'pkgver': '5.4.0.1055.38'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.4.0.1051.37'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-edge', 'pkgver': '5.4.0.1051.37'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke-5.4', 'pkgver': '5.4.0.1051.54~18.04.16'},
    {'osver': '18.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1022.23~18.04.23'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-edge', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1022-gkeop', 'pkgver': '5.4.0-1022.23~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1051-gcp', 'pkgver': '5.4.0-1051.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1051-gke', 'pkgver': '5.4.0-1051.54~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1053-oracle', 'pkgver': '5.4.0-1053.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1056-azure', 'pkgver': '5.4.0-1056.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-81-generic', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-81-lowlatency', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1022-gkeop', 'pkgver': '5.4.0-1022.23~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1051-gcp', 'pkgver': '5.4.0-1051.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1051-gke', 'pkgver': '5.4.0-1051.54~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1053-oracle', 'pkgver': '5.4.0-1053.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1055-aws', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1056-azure', 'pkgver': '5.4.0-1056.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-81-generic', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-81-generic-lpae', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-81-lowlatency', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1022-gkeop', 'pkgver': '5.4.0-1022.23~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1051-gcp', 'pkgver': '5.4.0-1051.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1051-gke', 'pkgver': '5.4.0-1051.54~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1053-oracle', 'pkgver': '5.4.0-1053.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1055-aws', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1056-azure', 'pkgver': '5.4.0-1056.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-81-generic', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.4.0.1055.38'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws-edge', 'pkgver': '5.4.0.1055.38'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure-edge', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.4.0.1051.37'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gcp-edge', 'pkgver': '5.4.0.1051.37'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gke-5.4', 'pkgver': '5.4.0.1051.54~18.04.16'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gkeop-5.4', 'pkgver': '5.4.0.1022.23~18.04.23'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle-edge', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-oem', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-oem-osp1', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-oracle', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-headers-5.4.0-1053', 'pkgver': '5.4.0-1053.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-tools-5.4.0-1053', 'pkgver': '5.4.0-1053.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-edge', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure-edge', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure-edge', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle-edge', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle-edge', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1022-gkeop', 'pkgver': '5.4.0-1022.23~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1051-gcp', 'pkgver': '5.4.0-1051.55~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1051-gke', 'pkgver': '5.4.0-1051.54~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1053-oracle', 'pkgver': '5.4.0-1053.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1055-aws', 'pkgver': '5.4.0-1055.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1056-azure', 'pkgver': '5.4.0-1056.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-81-generic', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-81-generic-lpae', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-81-lowlatency', 'pkgver': '5.4.0-81.91~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws', 'pkgver': '5.4.0.1055.38'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws-edge', 'pkgver': '5.4.0.1055.38'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure-edge', 'pkgver': '5.4.0.1056.36'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.4.0.1051.37'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gcp-edge', 'pkgver': '5.4.0.1051.37'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gke-5.4', 'pkgver': '5.4.0.1051.54~18.04.16'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gkeop-5.4', 'pkgver': '5.4.0.1022.23~18.04.23'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oem', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oem-osp1', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle-edge', 'pkgver': '5.4.0.1053.57~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-18.04', 'pkgver': '5.4.0.81.91~18.04.73'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.81.91~18.04.73'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-5.4-cloud-tools-5.4.0-1055 / etc');
}
