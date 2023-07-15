#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5039-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152536);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-22555");
  script_xref(name:"USN", value:"5039-1");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel vulnerability (USN-5039-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-5039-1 advisory.

  - A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c.
    This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name
    space (CVE-2021-22555)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5039-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22555");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter x_tables Heap OOB Write Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:block-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:crypto-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dasd-extra-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dasd-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fat-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fb-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firewire-core-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:floppy-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fs-core-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fs-secondary-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:input-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ipmi-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:irda-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kernel-image-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kernel-signed-image-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.4.0-1131");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.4.0-1131");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.4.0-1131");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1096-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1131-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-213-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-213-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1096-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1131-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-213");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-213-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-213-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1096-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1131-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-213");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-213-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-213-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-generic-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-virtual-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1096-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1131-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-213-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-213-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-hwe-generic-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-hwe-virtual-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.4.0-213-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.4.0-213-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-cloud-tools-4.4.0-1096");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-4.4.0-1096");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-4.4.0-1096");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1096-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1131-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-213-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-213-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.4.0-1131-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.4.0-213-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-4.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1096-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1131-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-213");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-213-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-213-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-udebs-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:md-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:message-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mouse-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:multipath-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nfs-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-pcmcia-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-shared-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-usb-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:parport-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pata-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pcmcia-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pcmcia-storage-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:plimodules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ppmodules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sata-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:scsi-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:serial-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:speakumodules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:storage-core-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:usb-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:virtio-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlan-modules-4.4.0-213-generic-di");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-22555');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5039-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '16.04', 'pkgname': 'block-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'crypto-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'dasd-extra-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'dasd-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'fat-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'fb-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'firewire-core-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'floppy-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'fs-core-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'fs-secondary-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'input-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'ipmi-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'irda-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'kernel-image-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'kernel-signed-image-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-aws', 'pkgver': '4.4.0.1131.136'},
    {'osver': '16.04', 'pkgname': 'linux-aws-cloud-tools-4.4.0-1131', 'pkgver': '4.4.0-1131.145'},
    {'osver': '16.04', 'pkgname': 'linux-aws-headers-4.4.0-1131', 'pkgver': '4.4.0-1131.145'},
    {'osver': '16.04', 'pkgname': 'linux-aws-tools-4.4.0-1131', 'pkgver': '4.4.0-1131.145'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-1096-kvm', 'pkgver': '4.4.0-1096.105'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-1131-aws', 'pkgver': '4.4.0-1131.145'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-213-generic', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-213-lowlatency', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-1096-kvm', 'pkgver': '4.4.0-1096.105'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-1131-aws', 'pkgver': '4.4.0-1131.145'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-213', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-213-generic', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-213-lowlatency', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-crashdump', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-generic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-1096-kvm', 'pkgver': '4.4.0-1096.105'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-1131-aws', 'pkgver': '4.4.0-1131.145'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-213', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-213-generic', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-213-lowlatency', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-headers-aws', 'pkgver': '4.4.0.1131.136'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '4.4.0.1096.94'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-generic-trusty', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-virtual-trusty', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1096-kvm', 'pkgver': '4.4.0-1096.105'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1131-aws', 'pkgver': '4.4.0-1131.145'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-213-generic', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-213-lowlatency', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws', 'pkgver': '4.4.0.1131.136'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-hwe-generic-trusty', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-hwe-virtual-trusty', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.4.0.1096.94'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.4.0-213-generic', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.4.0-213-lowlatency', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-kvm', 'pkgver': '4.4.0.1096.94'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-cloud-tools-4.4.0-1096', 'pkgver': '4.4.0-1096.105'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-headers-4.4.0-1096', 'pkgver': '4.4.0-1096.105'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-tools-4.4.0-1096', 'pkgver': '4.4.0-1096.105'},
    {'osver': '16.04', 'pkgname': 'linux-libc-dev', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-1096-kvm', 'pkgver': '4.4.0-1096.105'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-1131-aws', 'pkgver': '4.4.0-1131.145'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-213-generic', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-213-lowlatency', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.4.0-1131-aws', 'pkgver': '4.4.0-1131.145'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.4.0-213-generic', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '4.4.0.1131.136'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-source', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-source-4.4.0', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-1096-kvm', 'pkgver': '4.4.0-1096.105'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-1131-aws', 'pkgver': '4.4.0-1131.145'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-213', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-213-generic', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-213-lowlatency', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-tools-aws', 'pkgver': '4.4.0.1131.136'},
    {'osver': '16.04', 'pkgname': 'linux-tools-common', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-host', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '4.4.0.1096.94'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-udebs-generic', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'linux-virtual', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-utopic', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-vivid', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-wily', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-xenial', 'pkgver': '4.4.0.213.220'},
    {'osver': '16.04', 'pkgname': 'md-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'message-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'mouse-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'multipath-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'nfs-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'nic-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'nic-pcmcia-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'nic-shared-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'nic-usb-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'parport-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'pata-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'pcmcia-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'pcmcia-storage-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'plip-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'ppp-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'sata-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'scsi-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'serial-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'speakup-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'storage-core-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'usb-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'virtio-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'},
    {'osver': '16.04', 'pkgname': 'vlan-modules-4.4.0-213-generic-di', 'pkgver': '4.4.0-213.245'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'block-modules-4.4.0-213-generic-di / etc');
}
