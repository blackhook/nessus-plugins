#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5267-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157458);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");
  script_xref(name:"USN", value:"5267-2");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel regression (USN-5267-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by a vulnerability as referenced
in the USN-5267-2 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5267-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-cloud-tools-5.4.0-1065");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-headers-5.4.0-1065");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.4-tools-5.4.0-1065");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-5.4.0-1065");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-5.4.0-1065");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-5.4.0-1065");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1014-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1055-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1063-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1064-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1065-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-99-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-99-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-99-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-1065-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-99");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-99-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-99-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.4-headers-5.4.0-1064");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.4-tools-5.4.0-1064");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-5.4.0-1064");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-5.4.0-1064");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1014-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1055-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1063-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1064-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1065-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-99");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-99-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-99-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-99-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-ibm-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-cloud-tools-5.4.0-99");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-headers-5.4.0-99");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-tools-5.4.0-99");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.4-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-headers-5.4.0-1014");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-tools-5.4.0-1014");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ibm-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1014-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1055-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1063-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1064-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1065-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-99-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-99-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-99-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-ibm-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1014-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1055-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1063-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1064-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1065-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-99-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-99-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-5.4.0-1055");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-5.4.0-1055");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1014-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1055-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1063-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1064-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1065-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-99-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-99-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-99-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1014-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1063-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1064-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-1065-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-99-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-ibm-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-osp1-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-headers-5.4.0-1063");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.4-tools-5.4.0-1063");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-5.4.0-1063");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-5.4.0-1063");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1014-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1055-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1063-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1064-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1065-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-99");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-99-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-99-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-99-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-ibm-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
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
    {'osver': '18.04', 'pkgname': 'linux-aws', 'pkgver': '5.4.0.1065.47'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-cloud-tools-5.4.0-1065', 'pkgver': '5.4.0-1065.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-headers-5.4.0-1065', 'pkgver': '5.4.0-1065.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-aws-5.4-tools-5.4.0-1065', 'pkgver': '5.4.0-1065.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-aws-edge', 'pkgver': '5.4.0.1065.47'},
    {'osver': '18.04', 'pkgname': 'linux-azure', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-cloud-tools-5.4.0-1069', 'pkgver': '5.4.0-1069.72~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-headers-5.4.0-1069', 'pkgver': '5.4.0-1069.72~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-5.4-tools-5.4.0-1069', 'pkgver': '5.4.0-1069.72~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-azure-edge', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-99-generic', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-99-generic-lpae', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-99-generic', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure-edge', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-gkeop-5.4', 'pkgver': '5.4.0.1033.34~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-gcp', 'pkgver': '5.4.0.1064.49'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-5.4-headers-5.4.0-1064', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-5.4-tools-5.4.0-1064', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-edge', 'pkgver': '5.4.0.1064.49'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4', 'pkgver': '5.4.0.1062.65~18.04.26'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4-headers-5.4.0-1062', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gke-5.4-tools-5.4.0-1062', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4', 'pkgver': '5.4.0.1033.34~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-cloud-tools-5.4.0-1033', 'pkgver': '5.4.0-1033.34~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-headers-5.4.0-1033', 'pkgver': '5.4.0-1033.34~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-source-5.4.0', 'pkgver': '5.4.0-1033.34~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-gkeop-5.4-tools-5.4.0-1033', 'pkgver': '5.4.0-1033.34~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-99-generic', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-99-generic-lpae', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws', 'pkgver': '5.4.0.1065.47'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws-edge', 'pkgver': '5.4.0.1065.47'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure-edge', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.4.0.1064.49'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gcp-edge', 'pkgver': '5.4.0.1064.49'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gke-5.4', 'pkgver': '5.4.0.1062.65~18.04.26'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gkeop-5.4', 'pkgver': '5.4.0.1033.34~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oem', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oem-osp1', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle-edge', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-cloud-tools-5.4.0-99', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-cloud-tools-common', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-headers-5.4.0-99', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-source-5.4.0', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-tools-5.4.0-99', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-hwe-5.4-tools-common', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-99-generic', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-99-generic-lpae', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.4.0.1065.47'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-edge', 'pkgver': '5.4.0.1065.47'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.4.0.1064.49'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-edge', 'pkgver': '5.4.0.1064.49'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke-5.4', 'pkgver': '5.4.0.1062.65~18.04.26'},
    {'osver': '18.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1033.34~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-edge', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-99-generic', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-99-generic', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-99-generic-lpae', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-5.4.0-99-generic', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.4.0.1065.47'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws-edge', 'pkgver': '5.4.0.1065.47'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure-edge', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.4.0.1064.49'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gcp-edge', 'pkgver': '5.4.0.1064.49'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gke-5.4', 'pkgver': '5.4.0.1062.65~18.04.26'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gkeop-5.4', 'pkgver': '5.4.0.1033.34~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-oracle-edge', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-oem', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-oem-osp1', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-oracle', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-headers-5.4.0-1063', 'pkgver': '5.4.0-1063.67~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-5.4-tools-5.4.0-1063', 'pkgver': '5.4.0-1063.67~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-edge', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure-edge', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure-edge', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle-edge', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle-edge', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-99-generic', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-99-generic-lpae', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws', 'pkgver': '5.4.0.1065.47'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws-edge', 'pkgver': '5.4.0.1065.47'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure-edge', 'pkgver': '5.4.0.1069.48'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.4.0.1064.49'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gcp-edge', 'pkgver': '5.4.0.1064.49'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gke-5.4', 'pkgver': '5.4.0.1062.65~18.04.26'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gkeop-5.4', 'pkgver': '5.4.0.1033.34~18.04.33'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oem', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oem-osp1', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle-edge', 'pkgver': '5.4.0.1063.67~18.04.42'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-18.04', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.99.112~18.04.86'},
    {'osver': '20.04', 'pkgname': 'linux-aws-cloud-tools-5.4.0-1065', 'pkgver': '5.4.0-1065.68'},
    {'osver': '20.04', 'pkgname': 'linux-aws-headers-5.4.0-1065', 'pkgver': '5.4.0-1065.68'},
    {'osver': '20.04', 'pkgname': 'linux-aws-lts-20.04', 'pkgver': '5.4.0.1065.67'},
    {'osver': '20.04', 'pkgname': 'linux-aws-tools-5.4.0-1065', 'pkgver': '5.4.0-1065.68'},
    {'osver': '20.04', 'pkgname': 'linux-azure-cloud-tools-5.4.0-1069', 'pkgver': '5.4.0-1069.72'},
    {'osver': '20.04', 'pkgname': 'linux-azure-headers-5.4.0-1069', 'pkgver': '5.4.0-1069.72'},
    {'osver': '20.04', 'pkgname': 'linux-azure-lts-20.04', 'pkgver': '5.4.0.1069.67'},
    {'osver': '20.04', 'pkgname': 'linux-azure-tools-5.4.0-1069', 'pkgver': '5.4.0-1069.72'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1014-ibm', 'pkgver': '5.4.0-1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1055-kvm', 'pkgver': '5.4.0-1055.57'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-99-generic', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-99-generic-lpae', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-99', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-99-generic', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-azure-lts-20.04', 'pkgver': '5.4.0.1069.67'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-gkeop', 'pkgver': '5.4.0.1033.36'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-gkeop-5.4', 'pkgver': '5.4.0.1033.36'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-crashdump', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-headers-5.4.0-1064', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-lts-20.04', 'pkgver': '5.4.0.1064.74'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-tools-5.4.0-1064', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-generic', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-gke', 'pkgver': '5.4.0.1062.72'},
    {'osver': '20.04', 'pkgname': 'linux-gke-5.4', 'pkgver': '5.4.0.1062.72'},
    {'osver': '20.04', 'pkgname': 'linux-gke-headers-5.4.0-1062', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-gke-tools-5.4.0-1062', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop', 'pkgver': '5.4.0.1033.36'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-5.4', 'pkgver': '5.4.0.1033.36'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-cloud-tools-5.4.0-1033', 'pkgver': '5.4.0-1033.34'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-headers-5.4.0-1033', 'pkgver': '5.4.0-1033.34'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-source-5.4.0', 'pkgver': '5.4.0-1033.34'},
    {'osver': '20.04', 'pkgname': 'linux-gkeop-tools-5.4.0-1033', 'pkgver': '5.4.0-1033.34'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1014-ibm', 'pkgver': '5.4.0-1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1055-kvm', 'pkgver': '5.4.0-1055.57'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-99', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-99-generic', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-99-generic-lpae', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-headers-aws-lts-20.04', 'pkgver': '5.4.0.1065.67'},
    {'osver': '20.04', 'pkgname': 'linux-headers-azure-lts-20.04', 'pkgver': '5.4.0.1069.67'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gcp-lts-20.04', 'pkgver': '5.4.0.1064.74'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gke', 'pkgver': '5.4.0.1062.72'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gke-5.4', 'pkgver': '5.4.0.1062.72'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gkeop', 'pkgver': '5.4.0.1033.36'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gkeop-5.4', 'pkgver': '5.4.0.1033.36'},
    {'osver': '20.04', 'pkgname': 'linux-headers-ibm', 'pkgver': '5.4.0.1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-ibm-lts-20.04', 'pkgver': '5.4.0.1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '5.4.0.1055.54'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-osp1', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oracle-lts-20.04', 'pkgver': '5.4.0.1063.63'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-ibm', 'pkgver': '5.4.0.1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-ibm-cloud-tools-common', 'pkgver': '5.4.0-1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-ibm-headers-5.4.0-1014', 'pkgver': '5.4.0-1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-ibm-lts-20.04', 'pkgver': '5.4.0.1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-ibm-source-5.4.0', 'pkgver': '5.4.0-1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-ibm-tools-5.4.0-1014', 'pkgver': '5.4.0-1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-ibm-tools-common', 'pkgver': '5.4.0-1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1014-ibm', 'pkgver': '5.4.0-1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1055-kvm', 'pkgver': '5.4.0-1055.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-99-generic', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-99-generic-lpae', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws-lts-20.04', 'pkgver': '5.4.0.1065.67'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure-lts-20.04', 'pkgver': '5.4.0.1069.67'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-gcp-lts-20.04', 'pkgver': '5.4.0.1064.74'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-gke', 'pkgver': '5.4.0.1062.72'},
    {'osver': '20.04', 'pkgname': 'linux-image-gke-5.4', 'pkgver': '5.4.0.1062.72'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop', 'pkgver': '5.4.0.1033.36'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1033.36'},
    {'osver': '20.04', 'pkgname': 'linux-image-ibm', 'pkgver': '5.4.0.1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-ibm-lts-20.04', 'pkgver': '5.4.0.1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-kvm', 'pkgver': '5.4.0.1055.54'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle-lts-20.04', 'pkgver': '5.4.0.1063.63'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1014-ibm', 'pkgver': '5.4.0-1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1055-kvm', 'pkgver': '5.4.0-1055.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-99-generic', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-kvm', 'pkgver': '5.4.0.1055.54'},
    {'osver': '20.04', 'pkgname': 'linux-kvm-headers-5.4.0-1055', 'pkgver': '5.4.0-1055.57'},
    {'osver': '20.04', 'pkgname': 'linux-kvm-tools-5.4.0-1055', 'pkgver': '5.4.0-1055.57'},
    {'osver': '20.04', 'pkgname': 'linux-libc-dev', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1014-ibm', 'pkgver': '5.4.0-1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1055-kvm', 'pkgver': '5.4.0-1055.57'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-99-generic', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-99-generic-lpae', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1014-ibm', 'pkgver': '5.4.0-1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-99-generic', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-aws-lts-20.04', 'pkgver': '5.4.0.1065.67'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-azure-lts-20.04', 'pkgver': '5.4.0.1069.67'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gcp-lts-20.04', 'pkgver': '5.4.0.1064.74'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '5.4.0.1062.72'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gke-5.4', 'pkgver': '5.4.0.1062.72'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gkeop', 'pkgver': '5.4.0.1033.36'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gkeop-5.4', 'pkgver': '5.4.0.1033.36'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-ibm', 'pkgver': '5.4.0.1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-ibm-lts-20.04', 'pkgver': '5.4.0.1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-oem', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-oem-osp1', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-oem-osp1-tools-host', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-oem-tools-host', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-headers-5.4.0-1063', 'pkgver': '5.4.0-1063.67'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-lts-20.04', 'pkgver': '5.4.0.1063.63'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-tools-5.4.0-1063', 'pkgver': '5.4.0-1063.67'},
    {'osver': '20.04', 'pkgname': 'linux-source', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-source-5.4.0', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1014-ibm', 'pkgver': '5.4.0-1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1033-gkeop', 'pkgver': '5.4.0-1033.34'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1055-kvm', 'pkgver': '5.4.0-1055.57'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1062-gke', 'pkgver': '5.4.0-1062.65'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1063-oracle', 'pkgver': '5.4.0-1063.67'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1064-gcp', 'pkgver': '5.4.0-1064.68'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1065-aws', 'pkgver': '5.4.0-1065.68'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1069-azure', 'pkgver': '5.4.0-1069.72'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-99', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-99-generic', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-99-generic-lpae', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-99-lowlatency', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-tools-aws-lts-20.04', 'pkgver': '5.4.0.1065.67'},
    {'osver': '20.04', 'pkgname': 'linux-tools-azure-lts-20.04', 'pkgver': '5.4.0.1069.67'},
    {'osver': '20.04', 'pkgname': 'linux-tools-common', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gcp-lts-20.04', 'pkgver': '5.4.0.1064.74'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gke', 'pkgver': '5.4.0.1062.72'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gke-5.4', 'pkgver': '5.4.0.1062.72'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gkeop', 'pkgver': '5.4.0.1033.36'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gkeop-5.4', 'pkgver': '5.4.0.1033.36'},
    {'osver': '20.04', 'pkgname': 'linux-tools-host', 'pkgver': '5.4.0-99.112'},
    {'osver': '20.04', 'pkgname': 'linux-tools-ibm', 'pkgver': '5.4.0.1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-ibm-lts-20.04', 'pkgver': '5.4.0.1014.15'},
    {'osver': '20.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '5.4.0.1055.54'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-osp1', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oracle-lts-20.04', 'pkgver': '5.4.0.1063.63'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-virtual', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-18.04', 'pkgver': '5.4.0.99.103'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.99.103'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-5.4-cloud-tools-5.4.0-1065 / etc');
}
