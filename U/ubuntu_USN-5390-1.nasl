#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5390-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160214);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-1015", "CVE-2022-1016", "CVE-2022-26490");
  script_xref(name:"USN", value:"5390-1");

  script_name(english:"Ubuntu 22.04 LTS : Linux kernel vulnerabilities (USN-5390-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5390-1 advisory.

  - st21nfca_connectivity_event_received in drivers/nfc/st21nfca/se.c in the Linux kernel through 5.16.12 has
    EVT_TRANSACTION buffer overflows because of untrusted length parameters. (CVE-2022-26490)

  - A flaw was found in the Linux kernel in linux/net/netfilter/nf_tables_api.c of the netfilter subsystem.
    This flaw allows a local user to cause an out-of-bounds write issue. (CVE-2022-1015)

  - A flaw was found in the Linux kernel in net/netfilter/nf_tables_core.c:nft_do_chain, which can cause a
    use-after-free. This issue needs to handle 'return' with proper preconditions, as it can lead to a kernel
    information leak problem caused by a local, unprivileged attacker. (CVE-2022-1016)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5390-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26490");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.15.0-1003-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.15.0-1004-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.15.0-27-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.15.0-27-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.15.0-27-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.15.0-27-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.15.0-27-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.15.0-27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.15.0-27-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.15.0-27-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-5.15.0-1004");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-5.15.0-1004");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.15.0-1003-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.15.0-1004-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.15.0-27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.15.0-27-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.15.0-27-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.15.0-27-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.15.0-27-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.15.0-27-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-64k-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-64k-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-headers-5.15.0-1003");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-source-5.15.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-tools-5.15.0-1003");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1003-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1004-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-27-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-27-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-27-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-27-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-27-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-64k-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-64k-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.15.0-1003-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.15.0-1004-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.15.0-27-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.15.0-27-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.15.0-27-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.15.0-27-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-64k-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-64k-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-cloud-tools-5.15.0-27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-headers-5.15.0-27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-tools-5.15.0-27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.15.0-1003-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.15.0-1004-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.15.0-27-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.15.0-27-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.15.0-27-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.15.0-27-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.15.0-27-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.15.0-1003-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.15.0-1004-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.15.0-27-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.15.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.15.0-1003-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.15.0-1004-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.15.0-27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.15.0-27-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.15.0-27-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.15.0-27-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.15.0-27-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.15.0-27-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-64k-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-64k-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-22.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-22.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-22.04-edge");
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
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'linux-aws', 'pkgver': '5.15.0.1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-aws-cloud-tools-5.15.0-1005', 'pkgver': '5.15.0-1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-aws-headers-5.15.0-1005', 'pkgver': '5.15.0-1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-aws-tools-5.15.0-1005', 'pkgver': '5.15.0-1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-azure', 'pkgver': '5.15.0.1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-azure-cloud-tools-5.15.0-1005', 'pkgver': '5.15.0-1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-azure-headers-5.15.0-1005', 'pkgver': '5.15.0-1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-azure-tools-5.15.0-1005', 'pkgver': '5.15.0-1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-1003-gke', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-1003-ibm', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-1003-oracle', 'pkgver': '5.15.0-1003.5'},
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-1004-gcp', 'pkgver': '5.15.0-1004.7'},
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-1005-aws', 'pkgver': '5.15.0-1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-1005-azure', 'pkgver': '5.15.0-1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-1005-kvm', 'pkgver': '5.15.0-1005.5'},
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-27-generic', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-27-generic-64k', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-27-generic-lpae', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-27-lowlatency', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-27-lowlatency-64k', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-5.15.0-1005-aws', 'pkgver': '5.15.0-1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-5.15.0-1005-azure', 'pkgver': '5.15.0-1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-5.15.0-27', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-5.15.0-27-generic', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-5.15.0-27-lowlatency', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.15.0.1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-generic-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-generic-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-22.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-22.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-crashdump', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-gcp', 'pkgver': '5.15.0.1004.5'},
    {'osver': '22.04', 'pkgname': 'linux-gcp-headers-5.15.0-1004', 'pkgver': '5.15.0-1004.7'},
    {'osver': '22.04', 'pkgname': 'linux-gcp-tools-5.15.0-1004', 'pkgver': '5.15.0-1004.7'},
    {'osver': '22.04', 'pkgname': 'linux-generic', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-64k', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-64k-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-64k-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-64k-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-lpae-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-lpae-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-generic-lpae-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-gke', 'pkgver': '5.15.0.1003.7'},
    {'osver': '22.04', 'pkgname': 'linux-gke-5.15', 'pkgver': '5.15.0.1003.7'},
    {'osver': '22.04', 'pkgname': 'linux-gke-headers-5.15.0-1003', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-gke-tools-5.15.0-1003', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-1003-gke', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-1003-ibm', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-1003-oracle', 'pkgver': '5.15.0-1003.5'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-1004-gcp', 'pkgver': '5.15.0-1004.7'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-1005-aws', 'pkgver': '5.15.0-1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-1005-azure', 'pkgver': '5.15.0-1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-1005-kvm', 'pkgver': '5.15.0-1005.5'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-27', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-27-generic', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-27-generic-64k', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-27-generic-lpae', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-27-lowlatency', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-27-lowlatency-64k', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-aws', 'pkgver': '5.15.0.1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.15.0.1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.15.0.1004.5'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-64k', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-64k-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-64k-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-lpae-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-generic-lpae-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-gke', 'pkgver': '5.15.0.1003.7'},
    {'osver': '22.04', 'pkgname': 'linux-headers-gke-5.15', 'pkgver': '5.15.0.1003.7'},
    {'osver': '22.04', 'pkgname': 'linux-headers-ibm', 'pkgver': '5.15.0.1003.4'},
    {'osver': '22.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '5.15.0.1005.5'},
    {'osver': '22.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-lowlatency-64k', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-lowlatency-64k-hwe-20.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-lowlatency-64k-hwe-20.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-lowlatency-64k-hwe-22.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-lowlatency-64k-hwe-22.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-lowlatency-hwe-22.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-lowlatency-hwe-22.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-headers-oem-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.15.0.1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-virtual-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-virtual-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-headers-virtual-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-ibm', 'pkgver': '5.15.0.1003.4'},
    {'osver': '22.04', 'pkgname': 'linux-ibm-cloud-tools-common', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-ibm-headers-5.15.0-1003', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-ibm-source-5.15.0', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-ibm-tools-5.15.0-1003', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-ibm-tools-common', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-1003-gke', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-1003-ibm', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-1003-oracle', 'pkgver': '5.15.0-1003.5'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-1004-gcp', 'pkgver': '5.15.0-1004.7'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-1005-aws', 'pkgver': '5.15.0-1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-1005-azure', 'pkgver': '5.15.0-1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-1005-kvm', 'pkgver': '5.15.0-1005.5'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-27-generic', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-27-generic-64k', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-27-generic-lpae', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-27-lowlatency', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-27-lowlatency-64k', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.15.0.1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.15.0.1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-extra-virtual-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-extra-virtual-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.15.0.1004.5'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-64k-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-64k-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-lpae-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-generic-lpae-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-gke', 'pkgver': '5.15.0.1003.7'},
    {'osver': '22.04', 'pkgname': 'linux-image-gke-5.15', 'pkgver': '5.15.0.1003.7'},
    {'osver': '22.04', 'pkgname': 'linux-image-ibm', 'pkgver': '5.15.0.1003.4'},
    {'osver': '22.04', 'pkgname': 'linux-image-kvm', 'pkgver': '5.15.0.1005.5'},
    {'osver': '22.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-lowlatency-64k', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-lowlatency-64k-hwe-20.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-lowlatency-64k-hwe-20.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-lowlatency-64k-hwe-22.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-lowlatency-64k-hwe-22.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-lowlatency-hwe-22.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-lowlatency-hwe-22.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.15.0.1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-image-unsigned-5.15.0-1003-gke', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-image-unsigned-5.15.0-1003-ibm', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-image-unsigned-5.15.0-1003-oracle', 'pkgver': '5.15.0-1003.5'},
    {'osver': '22.04', 'pkgname': 'linux-image-unsigned-5.15.0-1004-gcp', 'pkgver': '5.15.0-1004.7'},
    {'osver': '22.04', 'pkgname': 'linux-image-unsigned-5.15.0-1005-aws', 'pkgver': '5.15.0-1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-image-unsigned-5.15.0-1005-azure', 'pkgver': '5.15.0-1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-image-unsigned-5.15.0-1005-kvm', 'pkgver': '5.15.0-1005.5'},
    {'osver': '22.04', 'pkgname': 'linux-image-unsigned-5.15.0-27-generic', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-unsigned-5.15.0-27-generic-64k', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-unsigned-5.15.0-27-lowlatency', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-unsigned-5.15.0-27-lowlatency-64k', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-virtual-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-image-virtual-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-kvm', 'pkgver': '5.15.0.1005.5'},
    {'osver': '22.04', 'pkgname': 'linux-kvm-headers-5.15.0-1005', 'pkgver': '5.15.0-1005.5'},
    {'osver': '22.04', 'pkgname': 'linux-kvm-tools-5.15.0-1005', 'pkgver': '5.15.0-1005.5'},
    {'osver': '22.04', 'pkgname': 'linux-libc-dev', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-64k', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-64k-hwe-20.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-64k-hwe-20.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-64k-hwe-22.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-64k-hwe-22.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-cloud-tools-5.15.0-27', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-cloud-tools-common', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-headers-5.15.0-27', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-hwe-20.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-hwe-22.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-hwe-22.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-tools-5.15.0-27', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-tools-common', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-lowlatency-tools-host', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-1003-gke', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-1003-ibm', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-1003-oracle', 'pkgver': '5.15.0-1003.5'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-1004-gcp', 'pkgver': '5.15.0-1004.7'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-1005-aws', 'pkgver': '5.15.0-1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-1005-azure', 'pkgver': '5.15.0-1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-1005-kvm', 'pkgver': '5.15.0-1005.5'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-27-generic', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-27-generic-64k', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-27-generic-lpae', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-27-lowlatency', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-27-lowlatency-64k', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-5.15.0-1003-gke', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-5.15.0-1003-ibm', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-5.15.0-1003-oracle', 'pkgver': '5.15.0-1003.5'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-5.15.0-1004-gcp', 'pkgver': '5.15.0-1004.7'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-5.15.0-1005-aws', 'pkgver': '5.15.0-1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-5.15.0-1005-azure', 'pkgver': '5.15.0-1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-5.15.0-27-generic', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.15.0.1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.15.0.1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.15.0.1004.5'},
    {'osver': '22.04', 'pkgname': 'linux-oem-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-oracle', 'pkgver': '5.15.0.1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-oracle-headers-5.15.0-1003', 'pkgver': '5.15.0-1003.5'},
    {'osver': '22.04', 'pkgname': 'linux-oracle-tools-5.15.0-1003', 'pkgver': '5.15.0-1003.5'},
    {'osver': '22.04', 'pkgname': 'linux-source', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-source-5.15.0', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-1003-gke', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-1003-ibm', 'pkgver': '5.15.0-1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-1003-oracle', 'pkgver': '5.15.0-1003.5'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-1004-gcp', 'pkgver': '5.15.0-1004.7'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-1005-aws', 'pkgver': '5.15.0-1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-1005-azure', 'pkgver': '5.15.0-1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-1005-kvm', 'pkgver': '5.15.0-1005.5'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-27', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-27-generic', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-27-generic-64k', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-27-generic-lpae', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-27-lowlatency', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-27-lowlatency-64k', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-aws', 'pkgver': '5.15.0.1005.7'},
    {'osver': '22.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.15.0.1005.6'},
    {'osver': '22.04', 'pkgname': 'linux-tools-common', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.15.0.1004.5'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-64k', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-64k-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-64k-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-lpae-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-generic-lpae-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-gke', 'pkgver': '5.15.0.1003.7'},
    {'osver': '22.04', 'pkgname': 'linux-tools-gke-5.15', 'pkgver': '5.15.0.1003.7'},
    {'osver': '22.04', 'pkgname': 'linux-tools-host', 'pkgver': '5.15.0-27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-ibm', 'pkgver': '5.15.0.1003.4'},
    {'osver': '22.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '5.15.0.1005.5'},
    {'osver': '22.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-lowlatency-64k', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-lowlatency-64k-hwe-20.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-lowlatency-64k-hwe-20.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-lowlatency-64k-hwe-22.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-lowlatency-64k-hwe-22.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-lowlatency-hwe-22.04', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-lowlatency-hwe-22.04-edge', 'pkgver': '5.15.0.27.28'},
    {'osver': '22.04', 'pkgname': 'linux-tools-oem-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.15.0.1003.3'},
    {'osver': '22.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-virtual-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-virtual-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-tools-virtual-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-virtual', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-virtual-hwe-20.04-edge', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-virtual-hwe-22.04', 'pkgver': '5.15.0.27.30'},
    {'osver': '22.04', 'pkgname': 'linux-virtual-hwe-22.04-edge', 'pkgver': '5.15.0.27.30'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-cloud-tools-5.15.0-1005 / etc');
}
