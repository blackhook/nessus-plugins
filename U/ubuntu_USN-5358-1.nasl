#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5358-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159373);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-1055", "CVE-2022-27666");
  script_xref(name:"USN", value:"5358-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : Linux kernel vulnerabilities (USN-5358-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5358-1 advisory.

  - A use-after-free exists in the Linux Kernel in tc_new_tfilter that could allow a local attacker to gain
    privilege escalation. The exploit requires unprivileged user namespaces. We recommend upgrading past
    commit 04c2a47ffb13c29778e2a14e414ad4cb5a5db4b5 (CVE-2022-1055)

  - A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and
    net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap
    objects and may cause a local privilege escalation threat. (CVE-2022-27666)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5358-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27666");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-5.13.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-5.4.0-1071");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-5.13.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-5.4.0-1071");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-5.13.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-5.4.0-1071");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-5.4.0-1074");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-5.4.0-1074");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-5.4.0-1074");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1020-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1025-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-39-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-39-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-39-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-39-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1061-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1069-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-107-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-107-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-107-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1071-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1074-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-39-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-39-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-107");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-107-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-107-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1071-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1074-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcheaders-5.13.0-1023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gctools-5.13.0-1023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1020-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1025-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-39-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-39-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-39-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-39-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1061-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1069-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-107");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-107-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-107-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-107-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1071-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1074-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-cloud-tools-5.13.0-39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-headers-5.13.0-39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-source-5.13.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-tools-5.13.0-39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.13-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-cloud-tools-5.4.0-107");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-headers-5.4.0-107");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-tools-5.4.0-107");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1020-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1025-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-39-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-39-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-39-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-39-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1061-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1069-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-107-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-107-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-107-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1071-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1074-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1020-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1025-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-39-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-39-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-39-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1061-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1069-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-107-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-107-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1071-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1074-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-5.13.0-1020");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-5.4.0-1061");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-5.13.0-1020");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-5.4.0-1061");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1020-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1025-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-39-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-39-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-39-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-39-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1061-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1069-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-107-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-107-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-107-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1071-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1074-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1025-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-39-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1069-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-107-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1071-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1074-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-osp1-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-headers-5.4.0-1069");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-tools-5.4.0-1069");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-5.13.0-1025");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-5.4.0-1069");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-5.13.0-1025");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-5.4.0-1069");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.13.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1020-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1023-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1025-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-39-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-39-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-39-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-39-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1061-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1069-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-107");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-107-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-107-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-107-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1071-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1074-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-107-generic', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-107-generic-lpae', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-107-generic', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-107-generic', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-107-generic-lpae', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oem', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oem-osp1', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle-edge', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-cloud-tools-5.4.0-107', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-cloud-tools-common', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-headers-5.4.0-107', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-source-5.4.0', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-tools-5.4.0-107', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-tools-common', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-107-generic', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-107-generic-lpae', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-edge', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-107-generic', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-107-generic', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-107-generic-lpae', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-107-generic', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle-edge', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-oem', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-oem-osp1', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-oracle', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-headers-5.4.0-1069', 'pkgver': '5.4.0-1069.75~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-tools-5.4.0-1069', 'pkgver': '5.4.0-1069.75~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-edge', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle-edge', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle-edge', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-107-generic', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-107-generic-lpae', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oem', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oem-osp1', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle-edge', 'pkgver': '5.4.0.1069.75~18.04.48'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-18.04', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.107.121~18.04.92'},
    {'osver': '20.04', 'pkgname': 'linux-aws-cloud-tools-5.4.0-1071', 'pkgver': '5.4.0-1071.76'},
    {'osver': '20.04', 'pkgname': 'linux-aws-headers-5.4.0-1071', 'pkgver': '5.4.0-1071.76'},
    {'osver': '20.04', 'pkgname': 'linux-aws-lts-20.04', 'pkgver': '5.4.0.1071.73'},
    {'osver': '20.04', 'pkgname': 'linux-aws-tools-5.4.0-1071', 'pkgver': '5.4.0-1071.76'},
    {'osver': '20.04', 'pkgname': 'linux-azure-cloud-tools-5.4.0-1074', 'pkgver': '5.4.0-1074.77'},
    {'osver': '20.04', 'pkgname': 'linux-azure-headers-5.4.0-1074', 'pkgver': '5.4.0-1074.77'},
    {'osver': '20.04', 'pkgname': 'linux-azure-lts-20.04', 'pkgver': '5.4.0.1074.72'},
    {'osver': '20.04', 'pkgname': 'linux-azure-tools-5.4.0-1074', 'pkgver': '5.4.0-1074.77'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.13.0-39-generic', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.13.0-39-generic-64k', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.13.0-39-generic-lpae', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1061-kvm', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-107-generic', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-107-generic-lpae', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1071-aws', 'pkgver': '5.4.0-1071.76'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1074-azure', 'pkgver': '5.4.0-1074.77'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.13.0-39-generic', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-107', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-107-generic', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1071-aws', 'pkgver': '5.4.0-1071.76'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1074-azure', 'pkgver': '5.4.0-1074.77'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-azure-lts-20.04', 'pkgver': '5.4.0.1074.72'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-crashdump', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-generic', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.13.0-39-generic', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.13.0-39-generic-64k', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.13.0-39-generic-lpae', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1061-kvm', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-107', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-107-generic', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-107-generic-lpae', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1071-aws', 'pkgver': '5.4.0-1071.76'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1074-azure', 'pkgver': '5.4.0-1074.77'},
    {'osver': '20.04', 'pkgname': 'linux-headers-aws-lts-20.04', 'pkgver': '5.4.0.1071.73'},
    {'osver': '20.04', 'pkgname': 'linux-headers-azure-lts-20.04', 'pkgver': '5.4.0.1074.72'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '5.4.0.1061.60'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-osp1', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oracle-lts-20.04', 'pkgver': '5.4.0.1069.69'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-cloud-tools-5.13.0-39', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-cloud-tools-common', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-headers-5.13.0-39', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-source-5.13.0', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-tools-5.13.0-39', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-tools-common', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.13-tools-host', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.13.0-39-generic', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.13.0-39-generic-64k', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.13.0-39-generic-lpae', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1061-kvm', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-107-generic', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-107-generic-lpae', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1071-aws', 'pkgver': '5.4.0-1071.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1074-azure', 'pkgver': '5.4.0-1074.77'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws-lts-20.04', 'pkgver': '5.4.0.1071.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure-lts-20.04', 'pkgver': '5.4.0.1074.72'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-image-kvm', 'pkgver': '5.4.0.1061.60'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle-lts-20.04', 'pkgver': '5.4.0.1069.69'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.13.0-39-generic', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.13.0-39-generic-64k', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1061-kvm', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-107-generic', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1071-aws', 'pkgver': '5.4.0-1071.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1074-azure', 'pkgver': '5.4.0-1074.77'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-kvm', 'pkgver': '5.4.0.1061.60'},
    {'osver': '20.04', 'pkgname': 'linux-kvm-headers-5.4.0-1061', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-kvm-tools-5.4.0-1061', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-libc-dev', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.13.0-39-generic', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.13.0-39-generic-64k', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.13.0-39-generic-lpae', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1061-kvm', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-107-generic', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-107-generic-lpae', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1071-aws', 'pkgver': '5.4.0-1071.76'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1074-azure', 'pkgver': '5.4.0-1074.77'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.13.0-39-generic', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-107-generic', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1071-aws', 'pkgver': '5.4.0-1071.76'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1074-azure', 'pkgver': '5.4.0-1074.77'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-aws-lts-20.04', 'pkgver': '5.4.0.1071.73'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-azure-lts-20.04', 'pkgver': '5.4.0.1074.72'},
    {'osver': '20.04', 'pkgname': 'linux-oem', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-oem-osp1', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-oem-osp1-tools-host', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-oem-tools-host', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-headers-5.4.0-1069', 'pkgver': '5.4.0-1069.75'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-lts-20.04', 'pkgver': '5.4.0.1069.69'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-tools-5.4.0-1069', 'pkgver': '5.4.0-1069.75'},
    {'osver': '20.04', 'pkgname': 'linux-source', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-source-5.4.0', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.13.0-39-generic', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.13.0-39-generic-64k', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.13.0-39-generic-lpae', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1061-kvm', 'pkgver': '5.4.0-1061.64'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1069-oracle', 'pkgver': '5.4.0-1069.75'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-107', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-107-generic', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-107-generic-lpae', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-107-lowlatency', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1071-aws', 'pkgver': '5.4.0-1071.76'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1074-azure', 'pkgver': '5.4.0-1074.77'},
    {'osver': '20.04', 'pkgname': 'linux-tools-aws-lts-20.04', 'pkgver': '5.4.0.1071.73'},
    {'osver': '20.04', 'pkgname': 'linux-tools-azure-lts-20.04', 'pkgver': '5.4.0.1074.72'},
    {'osver': '20.04', 'pkgname': 'linux-tools-common', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-tools-host', 'pkgver': '5.4.0-107.121'},
    {'osver': '20.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '5.4.0.1061.60'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-osp1', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oracle-lts-20.04', 'pkgver': '5.4.0.1069.69'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '20.04', 'pkgname': 'linux-virtual', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-18.04', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.107.111'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.13.0.39.44~20.04.24'},
    {'osver': '21.10', 'pkgname': 'linux-aws', 'pkgver': '5.13.0.1021.22'},
    {'osver': '21.10', 'pkgname': 'linux-aws-cloud-tools-5.13.0-1021', 'pkgver': '5.13.0-1021.23'},
    {'osver': '21.10', 'pkgname': 'linux-aws-headers-5.13.0-1021', 'pkgver': '5.13.0-1021.23'},
    {'osver': '21.10', 'pkgname': 'linux-aws-tools-5.13.0-1021', 'pkgver': '5.13.0-1021.23'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1020-kvm', 'pkgver': '5.13.0-1020.21'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1021-aws', 'pkgver': '5.13.0-1021.23'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1023-gcp', 'pkgver': '5.13.0-1023.28'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1025-oracle', 'pkgver': '5.13.0-1025.30'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-39-generic', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-39-generic-64k', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-39-generic-lpae', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-1021-aws', 'pkgver': '5.13.0-1021.23'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-39', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-39-generic', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-crashdump', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-gcp', 'pkgver': '5.13.0.1023.21'},
    {'osver': '21.10', 'pkgname': 'linux-gcp-headers-5.13.0-1023', 'pkgver': '5.13.0-1023.28'},
    {'osver': '21.10', 'pkgname': 'linux-gcp-tools-5.13.0-1023', 'pkgver': '5.13.0-1023.28'},
    {'osver': '21.10', 'pkgname': 'linux-generic', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-generic-64k', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-generic-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-gke', 'pkgver': '5.13.0.1023.21'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1020-kvm', 'pkgver': '5.13.0-1020.21'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1021-aws', 'pkgver': '5.13.0-1021.23'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1023-gcp', 'pkgver': '5.13.0-1023.28'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1025-oracle', 'pkgver': '5.13.0-1025.30'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-39', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-39-generic', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-39-generic-64k', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-39-generic-lpae', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-headers-aws', 'pkgver': '5.13.0.1021.22'},
    {'osver': '21.10', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.13.0.1023.21'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-64k', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-gke', 'pkgver': '5.13.0.1023.21'},
    {'osver': '21.10', 'pkgname': 'linux-headers-kvm', 'pkgver': '5.13.0.1020.20'},
    {'osver': '21.10', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-oem-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.13.0.1025.25'},
    {'osver': '21.10', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-headers-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1020-kvm', 'pkgver': '5.13.0-1020.21'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1021-aws', 'pkgver': '5.13.0-1021.23'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1023-gcp', 'pkgver': '5.13.0-1023.28'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1025-oracle', 'pkgver': '5.13.0-1025.30'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-39-generic', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-39-generic-64k', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-39-generic-lpae', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-image-aws', 'pkgver': '5.13.0.1021.22'},
    {'osver': '21.10', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-extra-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-gcp', 'pkgver': '5.13.0.1023.21'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-gke', 'pkgver': '5.13.0.1023.21'},
    {'osver': '21.10', 'pkgname': 'linux-image-kvm', 'pkgver': '5.13.0.1020.20'},
    {'osver': '21.10', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-oracle', 'pkgver': '5.13.0.1025.25'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1020-kvm', 'pkgver': '5.13.0-1020.21'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1021-aws', 'pkgver': '5.13.0-1021.23'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1023-gcp', 'pkgver': '5.13.0-1023.28'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1025-oracle', 'pkgver': '5.13.0-1025.30'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-39-generic', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-39-generic-64k', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-image-virtual', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-kvm', 'pkgver': '5.13.0.1020.20'},
    {'osver': '21.10', 'pkgname': 'linux-kvm-headers-5.13.0-1020', 'pkgver': '5.13.0-1020.21'},
    {'osver': '21.10', 'pkgname': 'linux-kvm-tools-5.13.0-1020', 'pkgver': '5.13.0-1020.21'},
    {'osver': '21.10', 'pkgname': 'linux-libc-dev', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-lowlatency', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1020-kvm', 'pkgver': '5.13.0-1020.21'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1021-aws', 'pkgver': '5.13.0-1021.23'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1023-gcp', 'pkgver': '5.13.0-1023.28'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1025-oracle', 'pkgver': '5.13.0-1025.30'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-39-generic', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-39-generic-64k', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-39-generic-lpae', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1021-aws', 'pkgver': '5.13.0-1021.23'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1023-gcp', 'pkgver': '5.13.0-1023.28'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1025-oracle', 'pkgver': '5.13.0-1025.30'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-39-generic', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.13.0.1021.22'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.13.0.1023.21'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '5.13.0.1023.21'},
    {'osver': '21.10', 'pkgname': 'linux-oem-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-oracle', 'pkgver': '5.13.0.1025.25'},
    {'osver': '21.10', 'pkgname': 'linux-oracle-headers-5.13.0-1025', 'pkgver': '5.13.0-1025.30'},
    {'osver': '21.10', 'pkgname': 'linux-oracle-tools-5.13.0-1025', 'pkgver': '5.13.0-1025.30'},
    {'osver': '21.10', 'pkgname': 'linux-source', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-source-5.13.0', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1020-kvm', 'pkgver': '5.13.0-1020.21'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1021-aws', 'pkgver': '5.13.0-1021.23'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1023-gcp', 'pkgver': '5.13.0-1023.28'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1025-oracle', 'pkgver': '5.13.0-1025.30'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-39', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-39-generic', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-39-generic-64k', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-39-generic-lpae', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-39-lowlatency', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-tools-aws', 'pkgver': '5.13.0.1021.22'},
    {'osver': '21.10', 'pkgname': 'linux-tools-common', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.13.0.1023.21'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-64k', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-gke', 'pkgver': '5.13.0.1023.21'},
    {'osver': '21.10', 'pkgname': 'linux-tools-host', 'pkgver': '5.13.0-39.44'},
    {'osver': '21.10', 'pkgname': 'linux-tools-kvm', 'pkgver': '5.13.0.1020.20'},
    {'osver': '21.10', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-oem-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.13.0.1025.25'},
    {'osver': '21.10', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-tools-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-virtual', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.13.0.39.48'},
    {'osver': '21.10', 'pkgname': 'linux-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.39.48'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-cloud-tools-5.13.0-1021 / etc');
}
