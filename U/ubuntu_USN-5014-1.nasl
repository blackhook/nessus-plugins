#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5014-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153130);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-33909");
  script_xref(name:"USN", value:"5014-1");
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 21.04 : Linux kernel vulnerability (USN-5014-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 21.04 host has packages installed that are affected by a vulnerability as
referenced in the USN-5014-1 advisory.

  - fs/seq_file.c in the Linux kernel 3.16 through 5.13.x before 5.13.4 does not properly restrict seq buffer
    allocations, leading to an integer overflow, an Out-of-bounds Write, and escalation to root by an
    unprivileged user, aka CID-8cae8cd89f05. (CVE-2021-33909)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5014-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33909");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:block-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:crypto-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fat-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fb-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firewire-core-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:floppy-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fs-core-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fs-secondary-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:input-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ipmi-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kernel-image-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kernel-signed-image-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.4.0-1094");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.4.0-1130");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-5.11.0-1014");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.4.0-1094");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.4.0-1130");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-5.11.0-1014");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.4.0-1094");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.4.0-1130");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-5.11.0-1014");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-5.11.0-1012");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-5.11.0-1012");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-5.11.0-1012");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-3.13.0-186-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-3.13.0-186-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-3.13.0-186-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1094-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1095-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1130-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-212-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-212-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1012-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1012-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1013-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1014-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1015-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1015-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-25-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-25-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-25-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-25-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.3.0-1042-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.3.0-1045-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.3.0-76-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.3.0-76-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-3.13.0-186");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-3.13.0-186-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-3.13.0-186-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1094-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1095-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1130-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-212");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-212-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-212-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-1012-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-25-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-25-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.3.0-76-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.3.0-76-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-gkeop-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-5.11.0-1014");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-5.11.0-1014");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-lts-saucy-eol-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-quantal-eol-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-raring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-raring-eol-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-saucy-eol-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.3-headers-5.3.0-1045");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke-5.3-tools-5.3.0-1045");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gkeop-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-3.13.0-186");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-3.13.0-186-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-3.13.0-186-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-3.13.0-186-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1094-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1095-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1130-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-212");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-212-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-212-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1012-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1012-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1013-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1014-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1015-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1015-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-25-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-25-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-25-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-25-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.3.0-1042-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.3.0-1045-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.3.0-76-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.3.0-76-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-raring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gkeop-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-cloud-tools-5.3.0-76");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-generic-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-headers-5.3.0-76");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-tools-5.3.0-76");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-udebs-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-virtual-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-186-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-186-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-186-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1094-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1095-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1130-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-212-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-212-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1012-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1012-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1013-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1014-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1015-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1015-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-25-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-25-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-25-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-25-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-1042-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-1045-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-76-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-76-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-xenial");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-raring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-hwe-generic-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-hwe-virtual-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-3.13.0-186-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-3.13.0-186-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.4.0-212-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.4.0-212-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1012-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1012-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1013-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1014-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-25-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-25-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-25-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.3.0-1045-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.3.0-76-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.3.0-76-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-cloud-tools-4.4.0-1095");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-4.4.0-1095");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-5.11.0-1012");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-4.4.0-1095");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-5.11.0-1012");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lts-xenial-cloud-tools-4.4.0-212");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lts-xenial-tools-4.4.0-212");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lts-xenial-udebs-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-3.13.0-186-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-3.13.0-186-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-3.13.0-186-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1094-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1095-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1130-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-212-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-212-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1012-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1012-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1013-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1014-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1015-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1015-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-25-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-25-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-25-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-25-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.3.0-1042-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.3.0-1045-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.3.0-76-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.3.0-76-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-3.13.0-186-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.4.0-1130-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.4.0-212-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1012-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1013-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1014-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-25-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.3.0-1045-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.3.0-76-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gkeop-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-5.11.0-1013");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-5.11.0-1013");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-headers-5.11.0-1015");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-tools-5.11.0-1015");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-5.3-headers-5.3.0-1042");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-5.3-tools-5.3.0-1042");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-quantal-eol-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-raring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-raring-eol-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-saucy-eol-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-raring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-trusty");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-3.13.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-4.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-3.13.0-186");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-3.13.0-186-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-3.13.0-186-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-3.13.0-186-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1094-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1095-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1130-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-212");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-212-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-212-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1012-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1012-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1013-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1014-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1014-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1015-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1015-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-25-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-25-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-25-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-25-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.3.0-1042-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.3.0-1045-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.3.0-76-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.3.0-76-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gkeop-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-raring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-udebs-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:md-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:message-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mouse-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:multipath-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nfs-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-pcmcia-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-shared-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-usb-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:parport-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pata-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pcmcia-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pcmcia-storage-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:plip-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ppp-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sata-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:scsi-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:serial-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:storage-core-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:usb-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:virtio-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlan-modules-5.3.0-76-generic-di");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (! preg(pattern:"^(16\.04|18\.04|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-33909');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5014-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '16.04', 'pkgname': 'linux-aws', 'pkgver': '4.4.0.1130.135'},
    {'osver': '16.04', 'pkgname': 'linux-aws-cloud-tools-4.4.0-1130', 'pkgver': '4.4.0-1130.144'},
    {'osver': '16.04', 'pkgname': 'linux-aws-headers-4.4.0-1130', 'pkgver': '4.4.0-1130.144'},
    {'osver': '16.04', 'pkgname': 'linux-aws-tools-4.4.0-1130', 'pkgver': '4.4.0-1130.144'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-1095-kvm', 'pkgver': '4.4.0-1095.104'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-1130-aws', 'pkgver': '4.4.0-1130.144'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-212-generic', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-212-lowlatency', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-1095-kvm', 'pkgver': '4.4.0-1095.104'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-1130-aws', 'pkgver': '4.4.0-1130.144'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-212', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-212-generic', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-212-lowlatency', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-crashdump', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-generic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-1095-kvm', 'pkgver': '4.4.0-1095.104'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-1130-aws', 'pkgver': '4.4.0-1130.144'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-212', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-212-generic', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-212-lowlatency', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-headers-aws', 'pkgver': '4.4.0.1130.135'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '4.4.0.1095.93'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-generic-trusty', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-virtual-trusty', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1095-kvm', 'pkgver': '4.4.0-1095.104'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1130-aws', 'pkgver': '4.4.0-1130.144'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-212-generic', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-212-lowlatency', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws', 'pkgver': '4.4.0.1130.135'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-hwe-generic-trusty', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-hwe-virtual-trusty', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.4.0.1095.93'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.4.0-212-generic', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.4.0-212-lowlatency', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-kvm', 'pkgver': '4.4.0.1095.93'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-cloud-tools-4.4.0-1095', 'pkgver': '4.4.0-1095.104'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-headers-4.4.0-1095', 'pkgver': '4.4.0-1095.104'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-tools-4.4.0-1095', 'pkgver': '4.4.0-1095.104'},
    {'osver': '16.04', 'pkgname': 'linux-libc-dev', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-1095-kvm', 'pkgver': '4.4.0-1095.104'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-1130-aws', 'pkgver': '4.4.0-1130.144'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-212-generic', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-212-lowlatency', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.4.0-1130-aws', 'pkgver': '4.4.0-1130.144'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.4.0-212-generic', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '4.4.0.1130.135'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-source', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-source-4.4.0', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-1095-kvm', 'pkgver': '4.4.0-1095.104'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-1130-aws', 'pkgver': '4.4.0-1130.144'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-212', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-212-generic', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-212-lowlatency', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-tools-aws', 'pkgver': '4.4.0.1130.135'},
    {'osver': '16.04', 'pkgname': 'linux-tools-common', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-host', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '4.4.0.1095.93'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-udebs-generic', 'pkgver': '4.4.0-212.244'},
    {'osver': '16.04', 'pkgname': 'linux-virtual', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-utopic', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-vivid', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-wily', 'pkgver': '4.4.0.212.219'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-xenial', 'pkgver': '4.4.0.212.219'},
    {'osver': '18.04', 'pkgname': 'block-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'crypto-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'fat-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'fb-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'firewire-core-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'floppy-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'fs-core-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'fs-secondary-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'input-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'ipmi-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'kernel-image-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'kernel-signed-image-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.3.0-1042-raspi2', 'pkgver': '5.3.0-1042.44'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.3.0-1045-gke', 'pkgver': '5.3.0-1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.3.0-76-generic', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.3.0-76-lowlatency', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.3.0-76-generic', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.3.0-76-lowlatency', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-gkeop-5.3', 'pkgver': '5.3.0.76.133'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.3', 'pkgver': '5.3.0.1045.28'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.3-headers-5.3.0-1045', 'pkgver': '5.3.0-1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.3-tools-5.3.0-1045', 'pkgver': '5.3.0-1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.3', 'pkgver': '5.3.0.76.133'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.3.0-1042-raspi2', 'pkgver': '5.3.0-1042.44'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.3.0-1045-gke', 'pkgver': '5.3.0-1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.3.0-76-generic', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.3.0-76-lowlatency', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gke-5.3', 'pkgver': '5.3.0.1045.28'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gkeop-5.3', 'pkgver': '5.3.0.76.133'},
    {'osver': '18.04', 'pkgname': 'linux-headers-raspi2-hwe-18.04', 'pkgver': '5.3.0.1042.31'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-cloud-tools-5.3.0-76', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-headers-5.3.0-76', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-tools-5.3.0-76', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-udebs-generic', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.3.0-1042-raspi2', 'pkgver': '5.3.0-1042.44'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.3.0-1045-gke', 'pkgver': '5.3.0-1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.3.0-76-generic', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.3.0-76-lowlatency', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke-5.3', 'pkgver': '5.3.0.1045.28'},
    {'osver': '18.04', 'pkgname': 'linux-image-gkeop-5.3', 'pkgver': '5.3.0.76.133'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi2-hwe-18.04', 'pkgver': '5.3.0.1042.31'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.3.0-1045-gke', 'pkgver': '5.3.0-1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.3.0-76-generic', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.3.0-76-lowlatency', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.3.0-1042-raspi2', 'pkgver': '5.3.0-1042.44'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.3.0-1045-gke', 'pkgver': '5.3.0-1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.3.0-76-generic', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.3.0-76-lowlatency', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.3.0-1045-gke', 'pkgver': '5.3.0-1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.3.0-76-generic', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gke-5.3', 'pkgver': '5.3.0.1045.28'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gkeop-5.3', 'pkgver': '5.3.0.76.133'},
    {'osver': '18.04', 'pkgname': 'linux-raspi2-5.3-headers-5.3.0-1042', 'pkgver': '5.3.0-1042.44'},
    {'osver': '18.04', 'pkgname': 'linux-raspi2-5.3-tools-5.3.0-1042', 'pkgver': '5.3.0-1042.44'},
    {'osver': '18.04', 'pkgname': 'linux-raspi2-hwe-18.04', 'pkgver': '5.3.0.1042.31'},
    {'osver': '18.04', 'pkgname': 'linux-source-5.3.0', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.3.0-1042-raspi2', 'pkgver': '5.3.0-1042.44'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.3.0-1045-gke', 'pkgver': '5.3.0-1045.48'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.3.0-76-generic', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.3.0-76-lowlatency', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gke-5.3', 'pkgver': '5.3.0.1045.28'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gkeop-5.3', 'pkgver': '5.3.0.76.133'},
    {'osver': '18.04', 'pkgname': 'linux-tools-raspi2-hwe-18.04', 'pkgver': '5.3.0.1042.31'},
    {'osver': '18.04', 'pkgname': 'md-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'message-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'mouse-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'multipath-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'nfs-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'nic-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'nic-pcmcia-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'nic-shared-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'nic-usb-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'parport-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'pata-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'pcmcia-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'pcmcia-storage-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'plip-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'ppp-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'sata-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'scsi-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'serial-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'storage-core-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'usb-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'virtio-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '18.04', 'pkgname': 'vlan-modules-5.3.0-76-generic-di', 'pkgver': '5.3.0-76.72'},
    {'osver': '21.04', 'pkgname': 'linux-aws', 'pkgver': '5.11.0.1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-aws-cloud-tools-5.11.0-1014', 'pkgver': '5.11.0-1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-aws-headers-5.11.0-1014', 'pkgver': '5.11.0-1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-aws-tools-5.11.0-1014', 'pkgver': '5.11.0-1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-azure', 'pkgver': '5.11.0.1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-azure-cloud-tools-5.11.0-1012', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-azure-headers-5.11.0-1012', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-azure-tools-5.11.0-1012', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1012-azure', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1012-kvm', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1013-oracle', 'pkgver': '5.11.0-1013.14'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1014-aws', 'pkgver': '5.11.0-1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1014-gcp', 'pkgver': '5.11.0-1014.16'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1015-raspi', 'pkgver': '5.11.0-1015.16'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1015-raspi-nolpae', 'pkgver': '5.11.0-1015.16'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-25-generic', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-25-generic-64k', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-25-generic-lpae', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-25-lowlatency', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-1012-azure', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-1014-aws', 'pkgver': '5.11.0-1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-25', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-25-generic', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-25-lowlatency', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.11.0.1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-crashdump', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-gcp', 'pkgver': '5.11.0.1014.14'},
    {'osver': '21.04', 'pkgname': 'linux-gcp-headers-5.11.0-1014', 'pkgver': '5.11.0-1014.16'},
    {'osver': '21.04', 'pkgname': 'linux-gcp-tools-5.11.0-1014', 'pkgver': '5.11.0-1014.16'},
    {'osver': '21.04', 'pkgname': 'linux-generic', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-generic-64k', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-generic-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-gke', 'pkgver': '5.11.0.1014.14'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1012-azure', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1012-kvm', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1013-oracle', 'pkgver': '5.11.0-1013.14'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1014-aws', 'pkgver': '5.11.0-1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1014-gcp', 'pkgver': '5.11.0-1014.16'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1015-raspi', 'pkgver': '5.11.0-1015.16'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1015-raspi-nolpae', 'pkgver': '5.11.0-1015.16'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-25', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-25-generic', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-25-generic-64k', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-25-generic-lpae', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-25-lowlatency', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-aws', 'pkgver': '5.11.0.1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.11.0.1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.11.0.1014.14'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-64k', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-gke', 'pkgver': '5.11.0.1014.14'},
    {'osver': '21.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '5.11.0.1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-oem-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.11.0.1013.14'},
    {'osver': '21.04', 'pkgname': 'linux-headers-raspi', 'pkgver': '5.11.0.1015.13'},
    {'osver': '21.04', 'pkgname': 'linux-headers-raspi-nolpae', 'pkgver': '5.11.0.1015.13'},
    {'osver': '21.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-headers-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1012-azure', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1012-kvm', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1013-oracle', 'pkgver': '5.11.0-1013.14'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1014-aws', 'pkgver': '5.11.0-1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1014-gcp', 'pkgver': '5.11.0-1014.16'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1015-raspi', 'pkgver': '5.11.0-1015.16'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1015-raspi-nolpae', 'pkgver': '5.11.0-1015.16'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-25-generic', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-25-generic-64k', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-25-generic-lpae', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-25-lowlatency', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.11.0.1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.11.0.1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.11.0.1014.14'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-gke', 'pkgver': '5.11.0.1014.14'},
    {'osver': '21.04', 'pkgname': 'linux-image-kvm', 'pkgver': '5.11.0.1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.11.0.1013.14'},
    {'osver': '21.04', 'pkgname': 'linux-image-raspi', 'pkgver': '5.11.0.1015.13'},
    {'osver': '21.04', 'pkgname': 'linux-image-raspi-nolpae', 'pkgver': '5.11.0.1015.13'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-1012-azure', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-1012-kvm', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-1013-oracle', 'pkgver': '5.11.0-1013.14'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-1014-gcp', 'pkgver': '5.11.0-1014.16'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-25-generic', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-25-generic-64k', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-25-lowlatency', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-kvm', 'pkgver': '5.11.0.1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-kvm-headers-5.11.0-1012', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-kvm-tools-5.11.0-1012', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-libc-dev', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-lowlatency', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1012-azure', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1012-kvm', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1013-oracle', 'pkgver': '5.11.0-1013.14'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1014-aws', 'pkgver': '5.11.0-1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1014-gcp', 'pkgver': '5.11.0-1014.16'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1015-raspi', 'pkgver': '5.11.0-1015.16'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1015-raspi-nolpae', 'pkgver': '5.11.0-1015.16'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-25-generic', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-25-generic-64k', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-25-generic-lpae', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-25-lowlatency', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-1012-azure', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-1013-oracle', 'pkgver': '5.11.0-1013.14'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-1014-aws', 'pkgver': '5.11.0-1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-1014-gcp', 'pkgver': '5.11.0-1014.16'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-25-generic', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.11.0.1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.11.0.1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.11.0.1014.14'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '5.11.0.1014.14'},
    {'osver': '21.04', 'pkgname': 'linux-oem-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-oracle', 'pkgver': '5.11.0.1013.14'},
    {'osver': '21.04', 'pkgname': 'linux-oracle-headers-5.11.0-1013', 'pkgver': '5.11.0-1013.14'},
    {'osver': '21.04', 'pkgname': 'linux-oracle-tools-5.11.0-1013', 'pkgver': '5.11.0-1013.14'},
    {'osver': '21.04', 'pkgname': 'linux-raspi', 'pkgver': '5.11.0.1015.13'},
    {'osver': '21.04', 'pkgname': 'linux-raspi-headers-5.11.0-1015', 'pkgver': '5.11.0-1015.16'},
    {'osver': '21.04', 'pkgname': 'linux-raspi-nolpae', 'pkgver': '5.11.0.1015.13'},
    {'osver': '21.04', 'pkgname': 'linux-raspi-tools-5.11.0-1015', 'pkgver': '5.11.0-1015.16'},
    {'osver': '21.04', 'pkgname': 'linux-source', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-source-5.11.0', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1012-azure', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1012-kvm', 'pkgver': '5.11.0-1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1013-oracle', 'pkgver': '5.11.0-1013.14'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1014-aws', 'pkgver': '5.11.0-1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1014-gcp', 'pkgver': '5.11.0-1014.16'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1015-raspi', 'pkgver': '5.11.0-1015.16'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1015-raspi-nolpae', 'pkgver': '5.11.0-1015.16'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-25', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-25-generic', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-25-generic-64k', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-25-generic-lpae', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-25-lowlatency', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-aws', 'pkgver': '5.11.0.1014.15'},
    {'osver': '21.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.11.0.1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-tools-common', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.11.0.1014.14'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-64k', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-gke', 'pkgver': '5.11.0.1014.14'},
    {'osver': '21.04', 'pkgname': 'linux-tools-host', 'pkgver': '5.11.0-25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '5.11.0.1012.13'},
    {'osver': '21.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-oem-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.11.0.1013.14'},
    {'osver': '21.04', 'pkgname': 'linux-tools-raspi', 'pkgver': '5.11.0.1015.13'},
    {'osver': '21.04', 'pkgname': 'linux-tools-raspi-nolpae', 'pkgver': '5.11.0.1015.13'},
    {'osver': '21.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-tools-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-virtual', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.11.0.25.27'},
    {'osver': '21.04', 'pkgname': 'linux-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.25.27'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'block-modules-5.3.0-76-generic-di / crypto-modules-5.3.0-76-generic-di / etc');
}
