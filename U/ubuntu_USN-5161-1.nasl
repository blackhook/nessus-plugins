#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5161-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155752);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2021-3655",
    "CVE-2021-3744",
    "CVE-2021-3764",
    "CVE-2021-42252"
  );
  script_xref(name:"USN", value:"5161-1");

  script_name(english:"Ubuntu 20.04 LTS / 21.04 : Linux kernel vulnerabilities (USN-5161-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 21.04 host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5161-1 advisory.

  - An issue was discovered in aspeed_lpc_ctrl_mmap in drivers/soc/aspeed/aspeed-lpc-ctrl.c in the Linux
    kernel before 5.14.6. Local attackers able to access the Aspeed LPC control interface could overwrite
    memory in the kernel and potentially execute privileges, aka CID-b49a0e69a7b1. This occurs because a
    certain comparison uses values that are not memory sizes. (CVE-2021-42252)

  - A vulnerability was found in the Linux kernel in versions prior to v5.14-rc1. Missing size validations on
    inbound SCTP packets may allow the kernel to read uninitialized memory. (CVE-2021-3655)

  - A memory leak flaw was found in the Linux kernel in the ccp_run_aes_gcm_cmd() function in
    drivers/crypto/ccp/ccp-ops.c, which allows attackers to cause a denial of service (memory consumption).
    This vulnerability is similar with the older CVE-2019-18808. (CVE-2021-3744)

  - A memory leak flaw was found in the Linux kernel's ccp_run_aes_gcm_cmd() function that allows an attacker
    to cause a denial of service. The vulnerability is similar to the older CVE-2019-18808. The highest threat
    from this vulnerability is to system availability. (CVE-2021-3764)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5161-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42252");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.11-cloud-tools-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.11-headers-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.11-tools-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.11-cloud-tools-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.11-headers-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.11-tools-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1020-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1022-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1022-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1022-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1023-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1023-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-41-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-41-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-41-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-41-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-1022-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-1022-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-41-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-41-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-edge");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.11-headers-5.11.0-1023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.11-tools-5.11.0-1023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-5.11.0-1023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-5.11.0-1023");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1020-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1022-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1022-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1022-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1023-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1023-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-41-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-41-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-41-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-41-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp-edge");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-cloud-tools-5.11.0-41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-headers-5.11.0-41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-source-5.11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-tools-5.11.0-41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1020-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1022-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1022-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1022-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1023-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1023-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-41-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-41-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-41-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-41-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-edge");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1020-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1022-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1022-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-41-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-41-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-41-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-5.11.0-1020");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-5.11.0-1020");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1020-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1022-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1022-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1022-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1023-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1023-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-41-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-41-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-41-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-41-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1022-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1022-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1022-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-41-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.11-headers-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.11-tools-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-headers-5.11.0-1023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-tools-5.11.0-1023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1020-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1022-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1022-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1022-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1023-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1023-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-41-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-41-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-41-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-41-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp-edge");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-edge");
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
if (! preg(pattern:"^(20\.04|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-3655', 'CVE-2021-3744', 'CVE-2021-3764', 'CVE-2021-42252');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5161-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '20.04', 'pkgname': 'linux-aws', 'pkgver': '5.11.0.1022.23~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-aws-5.11-cloud-tools-5.11.0-1022', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-aws-5.11-headers-5.11.0-1022', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-aws-5.11-tools-5.11.0-1022', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-aws-edge', 'pkgver': '5.11.0.1022.23~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-azure', 'pkgver': '5.11.0.1022.23~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-azure-5.11-cloud-tools-5.11.0-1022', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-azure-5.11-headers-5.11.0-1022', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-azure-5.11-tools-5.11.0-1022', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-azure-edge', 'pkgver': '5.11.0.1022.23~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-41-generic', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-41-generic-64k', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-41-generic-lpae', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.11.0-41-generic', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.11.0.1022.23~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-azure-edge', 'pkgver': '5.11.0.1022.23~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-gcp', 'pkgver': '5.11.0.1023.25~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-5.11-headers-5.11.0-1023', 'pkgver': '5.11.0-1023.25~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-5.11-tools-5.11.0-1023', 'pkgver': '5.11.0-1023.25~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-edge', 'pkgver': '5.11.0.1023.25~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-41-generic', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-41-generic-64k', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-41-generic-lpae', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-aws', 'pkgver': '5.11.0.1022.23~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-headers-aws-edge', 'pkgver': '5.11.0.1022.23~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.11.0.1022.23~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-headers-azure-edge', 'pkgver': '5.11.0.1022.23~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.11.0.1023.25~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gcp-edge', 'pkgver': '5.11.0.1023.25~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.11.0.1022.23~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oracle-edge', 'pkgver': '5.11.0.1022.23~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-cloud-tools-5.11.0-41', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-cloud-tools-common', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-headers-5.11.0-41', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-source-5.11.0', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-tools-5.11.0-41', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-tools-common', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-tools-host', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-41-generic', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-41-generic-64k', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-41-generic-lpae', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.11.0.1022.23~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws-edge', 'pkgver': '5.11.0.1022.23~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.11.0.1022.23~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '5.11.0.1022.23~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.11.0.1023.25~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-image-gcp-edge', 'pkgver': '5.11.0.1023.25~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.11.0.1022.23~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle-edge', 'pkgver': '5.11.0.1022.23~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-41-generic', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-41-generic-64k', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-41-generic', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-41-generic-64k', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-41-generic-lpae', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-41-generic', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.11.0.1022.23~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-aws-edge', 'pkgver': '5.11.0.1022.23~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.11.0.1022.23~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-azure-edge', 'pkgver': '5.11.0.1022.23~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.11.0.1023.25~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gcp-edge', 'pkgver': '5.11.0.1023.25~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-oracle', 'pkgver': '5.11.0.1022.23~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-5.11-headers-5.11.0-1022', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-5.11-tools-5.11.0-1022', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-edge', 'pkgver': '5.11.0.1022.23~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-41-generic', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-41-generic-64k', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-41-generic-lpae', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-aws', 'pkgver': '5.11.0.1022.23~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-tools-aws-edge', 'pkgver': '5.11.0.1022.23~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.11.0.1022.23~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-tools-azure-edge', 'pkgver': '5.11.0.1022.23~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.11.0.1023.25~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gcp-edge', 'pkgver': '5.11.0.1023.25~20.04.22'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.11.0.1022.23~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oracle-edge', 'pkgver': '5.11.0.1022.23~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.11.0.41.45~20.04.19'},
    {'osver': '21.04', 'pkgname': 'linux-aws', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-aws-cloud-tools-5.11.0-1022', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-aws-headers-5.11.0-1022', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-aws-tools-5.11.0-1022', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-azure', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-azure-cloud-tools-5.11.0-1022', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-azure-headers-5.11.0-1022', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-azure-tools-5.11.0-1022', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1020-kvm', 'pkgver': '5.11.0-1020.22'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1023-raspi', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1023-raspi-nolpae', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-41-generic', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-41-generic-64k', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-41-generic-lpae', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-41', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-41-generic', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-crashdump', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-gcp', 'pkgver': '5.11.0.1023.23'},
    {'osver': '21.04', 'pkgname': 'linux-gcp-headers-5.11.0-1023', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-gcp-tools-5.11.0-1023', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-generic', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-generic-64k', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-generic-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-gke', 'pkgver': '5.11.0.1023.23'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1020-kvm', 'pkgver': '5.11.0-1020.22'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1023-raspi', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1023-raspi-nolpae', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-41', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-41-generic', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-41-generic-64k', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-41-generic-lpae', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-headers-aws', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.11.0.1023.23'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-64k', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-gke', 'pkgver': '5.11.0.1023.23'},
    {'osver': '21.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '5.11.0.1020.21'},
    {'osver': '21.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-oem-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-headers-raspi', 'pkgver': '5.11.0.1023.21'},
    {'osver': '21.04', 'pkgname': 'linux-headers-raspi-nolpae', 'pkgver': '5.11.0.1023.21'},
    {'osver': '21.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-headers-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1020-kvm', 'pkgver': '5.11.0-1020.22'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1023-raspi', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1023-raspi-nolpae', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-41-generic', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-41-generic-64k', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-41-generic-lpae', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.11.0.1023.23'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-gke', 'pkgver': '5.11.0.1023.23'},
    {'osver': '21.04', 'pkgname': 'linux-image-kvm', 'pkgver': '5.11.0.1020.21'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-image-raspi', 'pkgver': '5.11.0.1023.21'},
    {'osver': '21.04', 'pkgname': 'linux-image-raspi-nolpae', 'pkgver': '5.11.0.1023.21'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-1020-kvm', 'pkgver': '5.11.0-1020.22'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-41-generic', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-41-generic-64k', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-kvm', 'pkgver': '5.11.0.1020.21'},
    {'osver': '21.04', 'pkgname': 'linux-kvm-headers-5.11.0-1020', 'pkgver': '5.11.0-1020.22'},
    {'osver': '21.04', 'pkgname': 'linux-kvm-tools-5.11.0-1020', 'pkgver': '5.11.0-1020.22'},
    {'osver': '21.04', 'pkgname': 'linux-libc-dev', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-lowlatency', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1020-kvm', 'pkgver': '5.11.0-1020.22'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1023-raspi', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1023-raspi-nolpae', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-41-generic', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-41-generic-64k', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-41-generic-lpae', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-41-generic', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.11.0.1023.23'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '5.11.0.1023.23'},
    {'osver': '21.04', 'pkgname': 'linux-oem-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-oracle', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-oracle-headers-5.11.0-1022', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-oracle-tools-5.11.0-1022', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-raspi', 'pkgver': '5.11.0.1023.21'},
    {'osver': '21.04', 'pkgname': 'linux-raspi-headers-5.11.0-1023', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-raspi-nolpae', 'pkgver': '5.11.0.1023.21'},
    {'osver': '21.04', 'pkgname': 'linux-raspi-tools-5.11.0-1023', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-source', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-source-5.11.0', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1020-kvm', 'pkgver': '5.11.0-1020.22'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1022-aws', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1022-azure', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1022-oracle', 'pkgver': '5.11.0-1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1023-gcp', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1023-raspi', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1023-raspi-nolpae', 'pkgver': '5.11.0-1023.25'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-41', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-41-generic', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-41-generic-64k', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-41-generic-lpae', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-41-lowlatency', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-tools-aws', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-tools-common', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.11.0.1023.23'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-64k', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-gke', 'pkgver': '5.11.0.1023.23'},
    {'osver': '21.04', 'pkgname': 'linux-tools-host', 'pkgver': '5.11.0-41.45'},
    {'osver': '21.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '5.11.0.1020.21'},
    {'osver': '21.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-oem-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.11.0.1022.23'},
    {'osver': '21.04', 'pkgname': 'linux-tools-raspi', 'pkgver': '5.11.0.1023.21'},
    {'osver': '21.04', 'pkgname': 'linux-tools-raspi-nolpae', 'pkgver': '5.11.0.1023.21'},
    {'osver': '21.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-tools-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-virtual', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.11.0.41.42'},
    {'osver': '21.04', 'pkgname': 'linux-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.41.42'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-5.11-cloud-tools-5.11.0-1022 / etc');
}
