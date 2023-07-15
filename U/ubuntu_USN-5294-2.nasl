#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5294-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158253);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-4083",
    "CVE-2021-4155",
    "CVE-2021-4202",
    "CVE-2021-22600",
    "CVE-2021-39685",
    "CVE-2021-43975",
    "CVE-2022-0330",
    "CVE-2022-22942"
  );
  script_xref(name:"USN", value:"5294-2");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/02");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-5294-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5294-2 advisory.

  - A double free bug in packet_set_ring() in net/packet/af_packet.c can be exploited by a local user through
    crafted syscalls to escalate privileges or deny service. We recommend upgrading kernel past the effected
    versions or rebuilding past ec6af094ea28f0f2dda1a6a33b14cd57e36a9755 (CVE-2021-22600)

  - A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges on the system.
    This flaw affects Linux kernel versions prior to 5.16-rc4. (CVE-2021-4083)

  - A use-after-free flaw was found in nci_request in net/nfc/nci/core.c in NFC Controller Interface (NCI) in
    the Linux kernel. This flaw could allow a local attacker with user privileges to cause a data race problem
    while the device is getting removed, leading to a privilege escalation problem. (CVE-2021-4202)

  - In various setup methods of the USB gadget subsystem, there is a possible out of bounds write due to an
    incorrect flag check. This could lead to local escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-210292376References: Upstream kernel (CVE-2021-39685)

  - In the Linux kernel through 5.15.2, hw_atl_utils_fw_rpc_wait in
    drivers/net/ethernet/aquantia/atlantic/hw_atl/hw_atl_utils.c allows an attacker (who can introduce a
    crafted device) to trigger an out-of-bounds write via a crafted length value. (CVE-2021-43975)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5294-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39685");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-cloud-tools-5.4.0-1066");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-headers-5.4.0-1066");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-tools-5.4.0-1066");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-5.4.0-1066");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-5.4.0-1066");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-5.4.0-1066");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-cloud-tools-5.4.0-1070");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-headers-5.4.0-1070");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.4-tools-5.4.0-1070");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-5.4.0-1070");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-fde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-5.4.0-1070");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-5.4.0-1070");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-100-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1015-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1034-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1056-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1064-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1065-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1066-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1070-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1034-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1066-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1070-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-fde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.4-headers-5.4.0-1065");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.4-tools-5.4.0-1065");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-5.4.0-1065");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-5.4.0-1065");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-cloud-tools-5.4.0-1034");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-headers-5.4.0-1034");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.4-tools-5.4.0-1034");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-cloud-tools-5.4.0-1034");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-headers-5.4.0-1034");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-tools-5.4.0-1034");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-100-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1015-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1034-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1056-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1064-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1065-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1066-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1070-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-fde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-ibm-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-ibm-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-cloud-tools-5.4.0-100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-headers-5.4.0-100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-tools-5.4.0-100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-5.4-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-5.4-headers-5.4.0-1015");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-5.4-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-5.4-tools-5.4.0-1015");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-5.4-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-headers-5.4.0-1015");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-tools-5.4.0-1015");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-100-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1015-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1034-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1056-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1064-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1065-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1066-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1070-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1070-azure-fde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-fde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-ibm-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-ibm-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1015-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1034-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1056-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1064-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1065-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1066-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1070-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1070-azure-fde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-5.4.0-1056");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-100-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1015-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1034-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1056-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1064-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1065-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1066-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1070-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1015-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1034-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1064-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1065-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1066-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1070-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-fde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-ibm-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-ibm-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-headers-5.4.0-1064");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-tools-5.4.0-1064");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-5.4.0-1064");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-5.4.0-1064");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-100-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1015-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1034-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1056-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1064-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1065-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1066-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1070-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-fde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-ibm-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-ibm-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-18.04-edge");
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
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'linux-aws', 'pkgver': '5.4.0.1066.48'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-cloud-tools-5.4.0-1066', 'pkgver': '5.4.0-1066.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-headers-5.4.0-1066', 'pkgver': '5.4.0-1066.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-tools-5.4.0-1066', 'pkgver': '5.4.0-1066.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-aws-edge', 'pkgver': '5.4.0.1066.48'},
    {'osver': '18.04', 'pkgname': 'linux-azure', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-cloud-tools-5.4.0-1070', 'pkgver': '5.4.0-1070.73~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-headers-5.4.0-1070', 'pkgver': '5.4.0-1070.73~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-tools-5.4.0-1070', 'pkgver': '5.4.0-1070.73~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-edge', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-100-generic', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-100-generic-lpae', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-100-generic', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure-edge', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-gkeop-5.4', 'pkgver': '5.4.0.1034.35~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-gcp', 'pkgver': '5.4.0.1065.50'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-5.4-headers-5.4.0-1065', 'pkgver': '5.4.0-1065.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-5.4-tools-5.4.0-1065', 'pkgver': '5.4.0-1065.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-edge', 'pkgver': '5.4.0.1065.50'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4', 'pkgver': '5.4.0.1034.35~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-cloud-tools-5.4.0-1034', 'pkgver': '5.4.0-1034.35~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-headers-5.4.0-1034', 'pkgver': '5.4.0-1034.35~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-source-5.4.0', 'pkgver': '5.4.0-1034.35~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-tools-5.4.0-1034', 'pkgver': '5.4.0-1034.35~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-100-generic', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-100-generic-lpae', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws', 'pkgver': '5.4.0.1066.48'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws-edge', 'pkgver': '5.4.0.1066.48'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure-edge', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.4.0.1065.50'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gcp-edge', 'pkgver': '5.4.0.1065.50'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gkeop-5.4', 'pkgver': '5.4.0.1034.35~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-headers-ibm', 'pkgver': '5.4.0.1015.32'},
    {'osver': '18.04', 'pkgname': 'linux-headers-ibm-edge', 'pkgver': '5.4.0.1015.32'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oem', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oem-osp1', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle-edge', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-cloud-tools-5.4.0-100', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-cloud-tools-common', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-headers-5.4.0-100', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-source-5.4.0', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-tools-5.4.0-100', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-tools-common', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-ibm', 'pkgver': '5.4.0.1015.32'},
    {'osver': '18.04', 'pkgname': 'linux-ibm-5.4-cloud-tools-common', 'pkgver': '5.4.0-1015.16~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-ibm-5.4-headers-5.4.0-1015', 'pkgver': '5.4.0-1015.16~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-ibm-5.4-source-5.4.0', 'pkgver': '5.4.0-1015.16~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-ibm-5.4-tools-5.4.0-1015', 'pkgver': '5.4.0-1015.16~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-ibm-5.4-tools-common', 'pkgver': '5.4.0-1015.16~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-ibm-edge', 'pkgver': '5.4.0.1015.32'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-100-generic', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-100-generic-lpae', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.4.0.1066.48'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-edge', 'pkgver': '5.4.0.1066.48'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.4.0.1065.50'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-edge', 'pkgver': '5.4.0.1065.50'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1034.35~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-image-ibm', 'pkgver': '5.4.0.1015.32'},
    {'osver': '18.04', 'pkgname': 'linux-image-ibm-edge', 'pkgver': '5.4.0.1015.32'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-edge', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-100-generic', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-100-generic', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-100-generic-lpae', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-100-generic', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.4.0.1066.48'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws-edge', 'pkgver': '5.4.0.1066.48'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure-edge', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.4.0.1065.50'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gcp-edge', 'pkgver': '5.4.0.1065.50'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gkeop-5.4', 'pkgver': '5.4.0.1034.35~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-ibm', 'pkgver': '5.4.0.1015.32'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-ibm-edge', 'pkgver': '5.4.0.1015.32'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle-edge', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-oem', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-oem-osp1', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-oracle', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-headers-5.4.0-1064', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-tools-5.4.0-1064', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-edge', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure-edge', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure-edge', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle-edge', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle-edge', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-100-generic', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-100-generic-lpae', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws', 'pkgver': '5.4.0.1066.48'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws-edge', 'pkgver': '5.4.0.1066.48'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure-edge', 'pkgver': '5.4.0.1070.49'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.4.0.1065.50'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gcp-edge', 'pkgver': '5.4.0.1065.50'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gkeop-5.4', 'pkgver': '5.4.0.1034.35~18.04.34'},
    {'osver': '18.04', 'pkgname': 'linux-tools-ibm', 'pkgver': '5.4.0.1015.32'},
    {'osver': '18.04', 'pkgname': 'linux-tools-ibm-edge', 'pkgver': '5.4.0.1015.32'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oem', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oem-osp1', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle-edge', 'pkgver': '5.4.0.1064.68~18.04.43'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-18.04', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.100.113~18.04.87'},
    {'osver': '20.04', 'pkgname': 'linux-aws-cloud-tools-5.4.0-1066', 'pkgver': '5.4.0-1066.69'},
    {'osver': '20.04', 'pkgname': 'linux-aws-headers-5.4.0-1066', 'pkgver': '5.4.0-1066.69'},
    {'osver': '20.04', 'pkgname': 'linux-aws-lts-20.04', 'pkgver': '5.4.0.1066.68'},
    {'osver': '20.04', 'pkgname': 'linux-aws-tools-5.4.0-1066', 'pkgver': '5.4.0-1066.69'},
    {'osver': '20.04', 'pkgname': 'linux-azure-cloud-tools-5.4.0-1070', 'pkgver': '5.4.0-1070.73'},
    {'osver': '20.04', 'pkgname': 'linux-azure-fde', 'pkgver': '5.4.0.1070.73+cvm1.16'},
    {'osver': '20.04', 'pkgname': 'linux-azure-headers-5.4.0-1070', 'pkgver': '5.4.0-1070.73'},
    {'osver': '20.04', 'pkgname': 'linux-azure-lts-20.04', 'pkgver': '5.4.0.1070.68'},
    {'osver': '20.04', 'pkgname': 'linux-azure-tools-5.4.0-1070', 'pkgver': '5.4.0-1070.73'},
    {'osver': '20.04', 'pkgname': 'linux-bluefield', 'pkgver': '5.4.0.1028.29'},
    {'osver': '20.04', 'pkgname': 'linux-bluefield-headers-5.4.0-1028', 'pkgver': '5.4.0-1028.31'},
    {'osver': '20.04', 'pkgname': 'linux-bluefield-tools-5.4.0-1028', 'pkgver': '5.4.0-1028.31'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1028-bluefield', 'pkgver': '5.4.0-1028.31'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1056-kvm', 'pkgver': '5.4.0-1056.58'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-azure-fde', 'pkgver': '5.4.0.1070.73+cvm1.16'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-azure-lts-20.04', 'pkgver': '5.4.0.1070.68'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-gkeop', 'pkgver': '5.4.0.1034.37'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-gkeop-5.4', 'pkgver': '5.4.0.1034.37'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-headers-5.4.0-1065', 'pkgver': '5.4.0-1065.69'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-lts-20.04', 'pkgver': '5.4.0.1065.75'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-tools-5.4.0-1065', 'pkgver': '5.4.0-1065.69'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop', 'pkgver': '5.4.0.1034.37'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-5.4', 'pkgver': '5.4.0.1034.37'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-cloud-tools-5.4.0-1034', 'pkgver': '5.4.0-1034.35'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-headers-5.4.0-1034', 'pkgver': '5.4.0-1034.35'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-source-5.4.0', 'pkgver': '5.4.0-1034.35'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-tools-5.4.0-1034', 'pkgver': '5.4.0-1034.35'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1028-bluefield', 'pkgver': '5.4.0-1028.31'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1056-kvm', 'pkgver': '5.4.0-1056.58'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73'},
    {'osver': '20.04', 'pkgname': 'linux-headers-aws-lts-20.04', 'pkgver': '5.4.0.1066.68'},
    {'osver': '20.04', 'pkgname': 'linux-headers-azure-fde', 'pkgver': '5.4.0.1070.73+cvm1.16'},
    {'osver': '20.04', 'pkgname': 'linux-headers-azure-lts-20.04', 'pkgver': '5.4.0.1070.68'},
    {'osver': '20.04', 'pkgname': 'linux-headers-bluefield', 'pkgver': '5.4.0.1028.29'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gcp-lts-20.04', 'pkgver': '5.4.0.1065.75'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gkeop', 'pkgver': '5.4.0.1034.37'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gkeop-5.4', 'pkgver': '5.4.0.1034.37'},
    {'osver': '20.04', 'pkgname': 'linux-headers-ibm', 'pkgver': '5.4.0.1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-headers-ibm-lts-20.04', 'pkgver': '5.4.0.1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '5.4.0.1056.55'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oracle-lts-20.04', 'pkgver': '5.4.0.1064.64'},
    {'osver': '20.04', 'pkgname': 'linux-ibm', 'pkgver': '5.4.0.1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-ibm-cloud-tools-common', 'pkgver': '5.4.0-1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-ibm-headers-5.4.0-1015', 'pkgver': '5.4.0-1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-ibm-lts-20.04', 'pkgver': '5.4.0.1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-ibm-source-5.4.0', 'pkgver': '5.4.0-1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-ibm-tools-5.4.0-1015', 'pkgver': '5.4.0-1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-ibm-tools-common', 'pkgver': '5.4.0-1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1028-bluefield', 'pkgver': '5.4.0-1028.31'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1056-kvm', 'pkgver': '5.4.0-1056.58'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1070-azure-fde', 'pkgver': '5.4.0-1070.73+cvm1.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws-lts-20.04', 'pkgver': '5.4.0.1066.68'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure-fde', 'pkgver': '5.4.0.1070.73+cvm1.16'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure-lts-20.04', 'pkgver': '5.4.0.1070.68'},
    {'osver': '20.04', 'pkgname': 'linux-image-bluefield', 'pkgver': '5.4.0.1028.29'},
    {'osver': '20.04', 'pkgname': 'linux-image-gcp-lts-20.04', 'pkgver': '5.4.0.1065.75'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop', 'pkgver': '5.4.0.1034.37'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1034.37'},
    {'osver': '20.04', 'pkgname': 'linux-image-ibm', 'pkgver': '5.4.0.1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-image-ibm-lts-20.04', 'pkgver': '5.4.0.1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-image-kvm', 'pkgver': '5.4.0.1056.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle-lts-20.04', 'pkgver': '5.4.0.1064.64'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1028-bluefield', 'pkgver': '5.4.0-1028.31'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1056-kvm', 'pkgver': '5.4.0-1056.58'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1070-azure-fde', 'pkgver': '5.4.0-1070.73+cvm1.1'},
    {'osver': '20.04', 'pkgname': 'linux-kvm', 'pkgver': '5.4.0.1056.55'},
    {'osver': '20.04', 'pkgname': 'linux-kvm-headers-5.4.0-1056', 'pkgver': '5.4.0-1056.58'},
    {'osver': '20.04', 'pkgname': 'linux-kvm-tools-5.4.0-1056', 'pkgver': '5.4.0-1056.58'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1028-bluefield', 'pkgver': '5.4.0-1028.31'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1056-kvm', 'pkgver': '5.4.0-1056.58'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-aws-lts-20.04', 'pkgver': '5.4.0.1066.68'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-azure-fde', 'pkgver': '5.4.0.1070.73+cvm1.16'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-azure-lts-20.04', 'pkgver': '5.4.0.1070.68'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gcp-lts-20.04', 'pkgver': '5.4.0.1065.75'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gkeop', 'pkgver': '5.4.0.1034.37'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gkeop-5.4', 'pkgver': '5.4.0.1034.37'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-ibm', 'pkgver': '5.4.0.1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-ibm-lts-20.04', 'pkgver': '5.4.0.1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-headers-5.4.0-1064', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-lts-20.04', 'pkgver': '5.4.0.1064.64'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-tools-5.4.0-1064', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1015-ibm', 'pkgver': '5.4.0-1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1028-bluefield', 'pkgver': '5.4.0-1028.31'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1034-gkeop', 'pkgver': '5.4.0-1034.35'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1056-kvm', 'pkgver': '5.4.0-1056.58'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1064-oracle', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1065-gcp', 'pkgver': '5.4.0-1065.69'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1066-aws', 'pkgver': '5.4.0-1066.69'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1070-azure', 'pkgver': '5.4.0-1070.73'},
    {'osver': '20.04', 'pkgname': 'linux-tools-aws-lts-20.04', 'pkgver': '5.4.0.1066.68'},
    {'osver': '20.04', 'pkgname': 'linux-tools-azure-fde', 'pkgver': '5.4.0.1070.73+cvm1.16'},
    {'osver': '20.04', 'pkgname': 'linux-tools-azure-lts-20.04', 'pkgver': '5.4.0.1070.68'},
    {'osver': '20.04', 'pkgname': 'linux-tools-bluefield', 'pkgver': '5.4.0.1028.29'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gcp-lts-20.04', 'pkgver': '5.4.0.1065.75'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gkeop', 'pkgver': '5.4.0.1034.37'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gkeop-5.4', 'pkgver': '5.4.0.1034.37'},
    {'osver': '20.04', 'pkgname': 'linux-tools-ibm', 'pkgver': '5.4.0.1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-tools-ibm-lts-20.04', 'pkgver': '5.4.0.1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '5.4.0.1056.55'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oracle-lts-20.04', 'pkgver': '5.4.0.1064.64'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-5.4-cloud-tools-5.4.0-1066 / etc');
}
