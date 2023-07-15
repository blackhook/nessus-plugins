#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5086-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153569);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");
  script_xref(name:"USN", value:"5086-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.04 : Linux kernel vulnerability (USN-5086-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.04 host has packages installed that are affected by a
vulnerability as referenced in the USN-5086-1 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5086-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-158-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-158-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-158-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-216-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-216-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-36-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-36-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-36-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-36-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-86-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-86-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-86-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-158");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-158-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-158-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-216");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-216-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-216-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-36-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-36-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-86-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-86-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-158");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-158-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-158-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-158-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-216");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-216-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-216-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-36-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-36-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-36-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-36-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-86-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-86-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-86-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-cloud-tools-5.11.0-36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-headers-5.11.0-36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-source-5.11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-tools-5.11.0-36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-cloud-tools-5.4.0-86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-headers-5.4.0-86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-tools-5.4.0-86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-cloud-tools-4.15.0-158");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-generic-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-tools-4.15.0-158");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-virtual-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-158-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-158-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-158-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-216-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-216-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-36-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-36-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-36-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-36-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-86-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-86-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-86-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-hwe-generic-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-hwe-virtual-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-158-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-158-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.4.0-216-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.4.0-216-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-36-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-36-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-36-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-86-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-86-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-158-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-158-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-158-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-216-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-216-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-36-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-36-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-36-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-36-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-86-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-86-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-86-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-158-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.4.0-216-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-36-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-86-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-osp1-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-4.15.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-4.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-158");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-158-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-158-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-158-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-216");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-216-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-216-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-36-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-36-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-36-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-36-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-86-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-86-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-86-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-xenial");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list();
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5086-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-158-generic', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-216-generic', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-216-lowlatency', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-158-generic', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-216', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-216-generic', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-216-lowlatency', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-crashdump', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-generic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-generic-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-158', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-158-generic', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-216', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-216-generic', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-216-lowlatency', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-oem', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-cloud-tools-4.15.0-158', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-generic-trusty', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-tools-4.15.0-158', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-virtual-trusty', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-158-generic', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-216-generic', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-216-lowlatency', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-hwe-generic-trusty', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-hwe-virtual-trusty', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-oem', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-158-generic', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.4.0-216-generic', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.4.0-216-lowlatency', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-libc-dev', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-158-generic', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-216-generic', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-216-lowlatency', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-158-generic', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.4.0-216-generic', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-oem', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-oem', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-signed-oem', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-source', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-source-4.15.0', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-source-4.4.0', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-158-generic', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-216', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-216-generic', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-216-lowlatency', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-tools-common', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-host', 'pkgver': '4.4.0-216.249'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-oem', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-virtual', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-hwe-16.04', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.158.151'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-utopic', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-vivid', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-wily', 'pkgver': '4.4.0.216.223'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-xenial', 'pkgver': '4.4.0.216.223'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-158-generic', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-158-generic-lpae', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-86-generic', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-86-generic-lpae', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-158', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-158-generic', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-86-generic', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-crashdump', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-generic', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-158', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-158-generic', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-158-generic-lpae', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-86-generic', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-86-generic-lpae', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oem', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oem-osp1', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-cloud-tools-5.4.0-86', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-cloud-tools-common', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-headers-5.4.0-86', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-source-5.4.0', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-tools-5.4.0-86', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-tools-common', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-158-generic', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-158-generic-lpae', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-86-generic', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-86-generic-lpae', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-158-generic', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-86-generic', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-libc-dev', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-158-generic', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-158-generic-lpae', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-86-generic', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-86-generic-lpae', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-158-generic', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-86-generic', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-oem', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-oem-osp1', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-source', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-source-4.15.0', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-158', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-158-generic', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-158-generic-lpae', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-158-lowlatency', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-86-generic', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-86-generic-lpae', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-common', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-tools-host', 'pkgver': '4.15.0-158.166'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oem', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oem-osp1', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-virtual', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-16.04', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.158.147'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-18.04', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.86.97~18.04.77'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-36-generic', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-36-generic-64k', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-36-generic-lpae', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-86-generic', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-86-generic-lpae', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.11.0-36-generic', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-86', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-86-generic', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-crashdump', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-generic', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-36-generic', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-36-generic-64k', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-36-generic-lpae', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-86', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-86-generic', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-86-generic-lpae', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-osp1', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-cloud-tools-5.11.0-36', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-cloud-tools-common', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-headers-5.11.0-36', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-source-5.11.0', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-tools-5.11.0-36', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-tools-common', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-tools-host', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-36-generic', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-36-generic-64k', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-36-generic-lpae', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-86-generic', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-86-generic-lpae', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-36-generic', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-36-generic-64k', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-86-generic', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-libc-dev', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-36-generic', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-36-generic-64k', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-36-generic-lpae', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-86-generic', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-86-generic-lpae', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-36-generic', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-86-generic', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-oem', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-oem-osp1', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-oem-osp1-tools-host', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-oem-tools-host', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-source', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-source-5.4.0', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-36-generic', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-36-generic-64k', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-36-generic-lpae', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-86', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-86-generic', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-86-generic-lpae', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-86-lowlatency', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-tools-common', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-host', 'pkgver': '5.4.0-86.97'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-osp1', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-virtual', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-18.04', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.86.90'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.36.40~20.04.15'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-36-generic', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-36-generic-64k', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-36-generic-lpae', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-36', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-36-generic', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-crashdump', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-generic', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-generic-64k', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-generic-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-36', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-36-generic', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-36-generic-64k', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-36-generic-lpae', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-64k', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-oem-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-headers-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-36-generic', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-36-generic-64k', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-36-generic-lpae', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-36-generic', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-36-generic-64k', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-libc-dev', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-lowlatency', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-36-generic', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-36-generic-64k', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-36-generic-lpae', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-36-generic', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-oem-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-source', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-source-5.11.0', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-36', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-36-generic', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-36-generic-64k', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-36-generic-lpae', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-36-lowlatency', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-tools-common', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-64k', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-host', 'pkgver': '5.11.0-36.40'},
    {'osver': '21.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-oem-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-tools-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-virtual', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.11.0.36.38'},
    {'osver': '21.04', 'pkgname': 'linux-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.36.38'}
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-buildinfo-4.15.0-158-generic / etc');
}
