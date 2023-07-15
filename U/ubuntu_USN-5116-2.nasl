#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5116-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154352);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-3702",
    "CVE-2021-3732",
    "CVE-2021-38198",
    "CVE-2021-38205",
    "CVE-2021-40490",
    "CVE-2021-42008"
  );
  script_xref(name:"USN", value:"5116-2");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-5116-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5116-2 advisory.

  - The decode_data function in drivers/net/hamradio/6pack.c in the Linux kernel before 5.13.13 has a slab
    out-of-bounds write. Input from a process that has the CAP_NET_ADMIN capability can lead to root access.
    (CVE-2021-42008)

  - u'Specifically timed and handcrafted traffic can cause internal errors in a WLAN device that lead to
    improper layer 2 Wi-Fi encryption with a consequent possibility of information disclosure over the air for
    a discrete set of traffic' in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon
    Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon
    Wearables, Snapdragon Wired Infrastructure and Networking in APQ8053, IPQ4019, IPQ8064, MSM8909W,
    MSM8996AU, QCA9531, QCN5502, QCS405, SDX20, SM6150, SM7150 (CVE-2020-3702)

  - arch/x86/kvm/mmu/paging_tmpl.h in the Linux kernel before 5.12.11 incorrectly computes the access
    permissions of a shadow page, leading to a missing guest protection page fault. (CVE-2021-38198)

  - drivers/net/ethernet/xilinx/xilinx_emaclite.c in the Linux kernel before 5.13.3 makes it easier for
    attackers to defeat an ASLR protection mechanism because it prints a kernel pointer (i.e., the real IOMEM
    pointer). (CVE-2021-38205)

  - A race condition was discovered in ext4_write_inline_data_end in fs/ext4/inline.c in the ext4 subsystem in
    the Linux kernel through 5.13.13. (CVE-2021-40490)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5116-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-cloud-tools-5.4.0-1058");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-headers-5.4.0-1058");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-tools-5.4.0-1058");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-5.4.0-1058");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-5.4.0-1058");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-5.4.0-1058");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-cloud-tools-5.4.0-1062");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-headers-5.4.0-1062");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-tools-5.4.0-1062");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-5.4.0-1062");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-5.4.0-1062");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-5.4.0-1062");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1025-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1045-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1054-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1056-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1058-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1062-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1025-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1058-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1062-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.4-headers-5.4.0-1054");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.4-tools-5.4.0-1054");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-headers-5.4.0-1054");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-tools-5.4.0-1054");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-cloud-tools-5.4.0-1025");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-headers-5.4.0-1025");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-tools-5.4.0-1025");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-cloud-tools-5.4.0-1025");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-headers-5.4.0-1025");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-tools-5.4.0-1025");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1025-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1045-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1054-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1056-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1058-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1062-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi2-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1025-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1045-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1054-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1056-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1058-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1062-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1025-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1054-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1056-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1062-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1025-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1045-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1054-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1056-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1058-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1062-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1025-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1054-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1056-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1058-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1062-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-headers-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-tools-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-5.4-headers-5.4.0-1045");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-5.4-tools-5.4.0-1045");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-headers-5.4.0-1045");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-tools-5.4.0-1045");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1025-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1045-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1054-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1056-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1058-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1062-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi2-hwe-18.04-edge");
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
if (! preg(pattern:"^(18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2020-3702', 'CVE-2021-3732', 'CVE-2021-38198', 'CVE-2021-38205', 'CVE-2021-40490');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5116-2');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '18.04', 'pkgname': 'linux-aws', 'pkgver': '5.4.0.1058.41'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-cloud-tools-5.4.0-1058', 'pkgver': '5.4.0-1058.61~18.04.3'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-headers-5.4.0-1058', 'pkgver': '5.4.0-1058.61~18.04.3'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-tools-5.4.0-1058', 'pkgver': '5.4.0-1058.61~18.04.3'},
    {'osver': '18.04', 'pkgname': 'linux-aws-edge', 'pkgver': '5.4.0.1058.41'},
    {'osver': '18.04', 'pkgname': 'linux-azure', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-cloud-tools-5.4.0-1062', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-headers-5.4.0-1062', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-tools-5.4.0-1062', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-edge', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1045-raspi', 'pkgver': '5.4.0-1045.49~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61~18.04.3'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61~18.04.3'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure-edge', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-gkeop-5.4', 'pkgver': '5.4.0.1025.26~18.04.26'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4', 'pkgver': '5.4.0.1054.57~18.04.19'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4-headers-5.4.0-1054', 'pkgver': '5.4.0-1054.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4-tools-5.4.0-1054', 'pkgver': '5.4.0-1054.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4', 'pkgver': '5.4.0.1025.26~18.04.26'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-cloud-tools-5.4.0-1025', 'pkgver': '5.4.0-1025.26~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-headers-5.4.0-1025', 'pkgver': '5.4.0-1025.26~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-source-5.4.0', 'pkgver': '5.4.0-1025.26~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-tools-5.4.0-1025', 'pkgver': '5.4.0-1025.26~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1045-raspi', 'pkgver': '5.4.0-1045.49~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61~18.04.3'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws', 'pkgver': '5.4.0.1058.41'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws-edge', 'pkgver': '5.4.0.1058.41'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure-edge', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gke-5.4', 'pkgver': '5.4.0.1054.57~18.04.19'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gkeop-5.4', 'pkgver': '5.4.0.1025.26~18.04.26'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle-edge', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-headers-raspi-hwe-18.04', 'pkgver': '5.4.0.1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-headers-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1045-raspi', 'pkgver': '5.4.0-1045.49~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61~18.04.3'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.4.0.1058.41'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-edge', 'pkgver': '5.4.0.1058.41'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke-5.4', 'pkgver': '5.4.0.1054.57~18.04.19'},
    {'osver': '18.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1025.26~18.04.26'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-edge', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi-hwe-18.04', 'pkgver': '5.4.0.1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1045-raspi', 'pkgver': '5.4.0-1045.49~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61~18.04.3'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61~18.04.3'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.4.0.1058.41'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws-edge', 'pkgver': '5.4.0.1058.41'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure-edge', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gke-5.4', 'pkgver': '5.4.0.1054.57~18.04.19'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gkeop-5.4', 'pkgver': '5.4.0.1025.26~18.04.26'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle-edge', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-oracle', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-headers-5.4.0-1056', 'pkgver': '5.4.0-1056.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-tools-5.4.0-1056', 'pkgver': '5.4.0-1056.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-edge', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-raspi-5.4-headers-5.4.0-1045', 'pkgver': '5.4.0-1045.49~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-raspi-5.4-tools-5.4.0-1045', 'pkgver': '5.4.0-1045.49~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-raspi-hwe-18.04', 'pkgver': '5.4.0.1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure-edge', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure-edge', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle-edge', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle-edge', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1045-raspi', 'pkgver': '5.4.0-1045.49~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61~18.04.3'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws', 'pkgver': '5.4.0.1058.41'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws-edge', 'pkgver': '5.4.0.1058.41'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure-edge', 'pkgver': '5.4.0.1062.42'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gke-5.4', 'pkgver': '5.4.0.1054.57~18.04.19'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gkeop-5.4', 'pkgver': '5.4.0.1025.26~18.04.26'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle-edge', 'pkgver': '5.4.0.1056.60~18.04.36'},
    {'osver': '18.04', 'pkgname': 'linux-tools-raspi-hwe-18.04', 'pkgver': '5.4.0.1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-tools-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1045.48'},
    {'osver': '20.04', 'pkgname': 'linux-aws-cloud-tools-5.4.0-1058', 'pkgver': '5.4.0-1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-aws-headers-5.4.0-1058', 'pkgver': '5.4.0-1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-aws-lts-20.04', 'pkgver': '5.4.0.1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-aws-tools-5.4.0-1058', 'pkgver': '5.4.0-1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-azure-cloud-tools-5.4.0-1062', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-azure-headers-5.4.0-1062', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-azure-lts-20.04', 'pkgver': '5.4.0.1062.60'},
    {'osver': '20.04', 'pkgname': 'linux-azure-tools-5.4.0-1062', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1045-raspi', 'pkgver': '5.4.0-1045.49'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-azure-lts-20.04', 'pkgver': '5.4.0.1062.60'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-gkeop', 'pkgver': '5.4.0.1025.28'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-gkeop-5.4', 'pkgver': '5.4.0.1025.28'},
    {'osver': '20.04', 'pkgname': 'linux-gke', 'pkgver': '5.4.0.1054.64'},
    {'osver': '20.04', 'pkgname': 'linux-gke-5.4', 'pkgver': '5.4.0.1054.64'},
    {'osver': '20.04', 'pkgname': 'linux-gke-headers-5.4.0-1054', 'pkgver': '5.4.0-1054.57'},
    {'osver': '20.04', 'pkgname': 'linux-gke-tools-5.4.0-1054', 'pkgver': '5.4.0-1054.57'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop', 'pkgver': '5.4.0.1025.28'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-5.4', 'pkgver': '5.4.0.1025.28'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-cloud-tools-5.4.0-1025', 'pkgver': '5.4.0-1025.26'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-headers-5.4.0-1025', 'pkgver': '5.4.0-1025.26'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-source-5.4.0', 'pkgver': '5.4.0-1025.26'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-tools-5.4.0-1025', 'pkgver': '5.4.0-1025.26'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1045-raspi', 'pkgver': '5.4.0-1045.49'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-headers-aws-lts-20.04', 'pkgver': '5.4.0.1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-headers-azure-lts-20.04', 'pkgver': '5.4.0.1062.60'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gke', 'pkgver': '5.4.0.1054.64'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gke-5.4', 'pkgver': '5.4.0.1054.64'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gkeop', 'pkgver': '5.4.0.1025.28'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gkeop-5.4', 'pkgver': '5.4.0.1025.28'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oracle-lts-20.04', 'pkgver': '5.4.0.1056.56'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi-hwe-18.04', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi2', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi2-hwe-18.04', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1045-raspi', 'pkgver': '5.4.0-1045.49'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws-lts-20.04', 'pkgver': '5.4.0.1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure-lts-20.04', 'pkgver': '5.4.0.1062.60'},
    {'osver': '20.04', 'pkgname': 'linux-image-gke', 'pkgver': '5.4.0.1054.64'},
    {'osver': '20.04', 'pkgname': 'linux-image-gke-5.4', 'pkgver': '5.4.0.1054.64'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop', 'pkgver': '5.4.0.1025.28'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1025.28'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle-lts-20.04', 'pkgver': '5.4.0.1056.56'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi-hwe-18.04', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2-hwe-18.04', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1045-raspi', 'pkgver': '5.4.0-1045.49'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-aws-lts-20.04', 'pkgver': '5.4.0.1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-azure-lts-20.04', 'pkgver': '5.4.0.1062.60'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '5.4.0.1054.64'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gke-5.4', 'pkgver': '5.4.0.1054.64'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gkeop', 'pkgver': '5.4.0.1025.28'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gkeop-5.4', 'pkgver': '5.4.0.1025.28'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-headers-5.4.0-1056', 'pkgver': '5.4.0-1056.60'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-lts-20.04', 'pkgver': '5.4.0.1056.56'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-tools-5.4.0-1056', 'pkgver': '5.4.0-1056.60'},
    {'osver': '20.04', 'pkgname': 'linux-raspi', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-raspi-headers-5.4.0-1045', 'pkgver': '5.4.0-1045.49'},
    {'osver': '20.04', 'pkgname': 'linux-raspi-hwe-18.04', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-raspi-tools-5.4.0-1045', 'pkgver': '5.4.0-1045.49'},
    {'osver': '20.04', 'pkgname': 'linux-raspi2', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-raspi2-hwe-18.04', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1025-gkeop', 'pkgver': '5.4.0-1025.26'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1045-raspi', 'pkgver': '5.4.0-1045.49'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1054-gke', 'pkgver': '5.4.0-1054.57'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1056-oracle', 'pkgver': '5.4.0-1056.60'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1058-aws', 'pkgver': '5.4.0-1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1062-azure', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-tools-aws-lts-20.04', 'pkgver': '5.4.0.1058.61'},
    {'osver': '20.04', 'pkgname': 'linux-tools-azure-lts-20.04', 'pkgver': '5.4.0.1062.60'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gke', 'pkgver': '5.4.0.1054.64'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gke-5.4', 'pkgver': '5.4.0.1054.64'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gkeop', 'pkgver': '5.4.0.1025.28'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gkeop-5.4', 'pkgver': '5.4.0.1025.28'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oracle-lts-20.04', 'pkgver': '5.4.0.1056.56'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi-hwe-18.04', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi2', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi2-hwe-18.04', 'pkgver': '5.4.0.1045.80'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1045.80'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-5.4-cloud-tools-5.4.0-1058 / etc');
}
