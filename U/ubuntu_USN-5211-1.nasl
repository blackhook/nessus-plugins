#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5211-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156483);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-4002");
  script_xref(name:"USN", value:"5211-1");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel vulnerability (USN-5211-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-5211-1 advisory.

  - A memory leak flaw in the Linux kernel's hugetlbfs memory usage was found in the way the user maps some
    regions of memory twice using shmget() which are aligned to PUD alignment with the fault of some of the
    memory pages. A local user could use this flaw to get unauthorized access to some data. (CVE-2021-4002)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5211-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4002");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hv-kvp-daemon-init");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.4.0-1098");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.4.0-1134");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.4.0-1098");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.4.0-1134");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.4.0-1098");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.4.0-1134");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-3.13.0-189-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-3.13.0-189-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-3.13.0-189-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1098-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1099-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-1134-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-218-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.4.0-218-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-3.13.0-189");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-3.13.0-189-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-3.13.0-189-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1098-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1099-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-1134-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-218");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-218-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.4.0-218-lowlatency");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-3.13.0-189");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-3.13.0-189-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-3.13.0-189-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-3.13.0-189-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1098-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1099-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-1134-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-218");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-218-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.4.0-218-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-generic-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-virtual-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-189-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-189-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-189-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1098-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1099-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1134-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-218-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-218-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-hwe-generic-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-hwe-virtual-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-3.13.0-189-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-3.13.0-189-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.4.0-218-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.4.0-218-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-cloud-tools-4.4.0-1099");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-4.4.0-1099");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-4.4.0-1099");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lts-xenial-cloud-tools-4.4.0-218");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lts-xenial-tools-4.4.0-218");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-3.13.0-189-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-3.13.0-189-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-3.13.0-189-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1098-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1099-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-1134-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-218-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.4.0-218-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-3.13.0-189-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.4.0-1134-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.4.0-218-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-3.13.0-189");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-3.13.0-189-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-3.13.0-189-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-3.13.0-189-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1098-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1099-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-1134-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-218");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-218-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.4.0-218-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lts-trusty");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-quantal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-raring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-saucy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-trusty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-utopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-vivid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-wily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-lts-xenial");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var cve_list = make_list('CVE-2021-4002');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5211-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '16.04', 'pkgname': 'linux-aws', 'pkgver': '4.4.0.1134.139'},
    {'osver': '16.04', 'pkgname': 'linux-aws-cloud-tools-4.4.0-1134', 'pkgver': '4.4.0-1134.148'},
    {'osver': '16.04', 'pkgname': 'linux-aws-headers-4.4.0-1134', 'pkgver': '4.4.0-1134.148'},
    {'osver': '16.04', 'pkgname': 'linux-aws-tools-4.4.0-1134', 'pkgver': '4.4.0-1134.148'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-1099-kvm', 'pkgver': '4.4.0-1099.108'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-1134-aws', 'pkgver': '4.4.0-1134.148'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-218-generic', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.4.0-218-lowlatency', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-1099-kvm', 'pkgver': '4.4.0-1099.108'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-1134-aws', 'pkgver': '4.4.0-1134.148'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-218', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-218-generic', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.4.0-218-lowlatency', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-crashdump', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-generic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-generic-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-1099-kvm', 'pkgver': '4.4.0-1099.108'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-1134-aws', 'pkgver': '4.4.0-1134.148'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-218', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-218-generic', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.4.0-218-lowlatency', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-headers-aws', 'pkgver': '4.4.0.1134.139'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '4.4.0.1099.97'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-generic-trusty', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-virtual-trusty', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1099-kvm', 'pkgver': '4.4.0-1099.108'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-1134-aws', 'pkgver': '4.4.0-1134.148'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-218-generic', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.4.0-218-lowlatency', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws', 'pkgver': '4.4.0.1134.139'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-hwe-generic-trusty', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-hwe-virtual-trusty', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.4.0.1099.97'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.4.0-218-generic', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.4.0-218-lowlatency', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-kvm', 'pkgver': '4.4.0.1099.97'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-cloud-tools-4.4.0-1099', 'pkgver': '4.4.0-1099.108'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-headers-4.4.0-1099', 'pkgver': '4.4.0-1099.108'},
    {'osver': '16.04', 'pkgname': 'linux-kvm-tools-4.4.0-1099', 'pkgver': '4.4.0-1099.108'},
    {'osver': '16.04', 'pkgname': 'linux-libc-dev', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-1099-kvm', 'pkgver': '4.4.0-1099.108'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-1134-aws', 'pkgver': '4.4.0-1134.148'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-218-generic', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.4.0-218-lowlatency', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.4.0-1134-aws', 'pkgver': '4.4.0-1134.148'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.4.0-218-generic', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '4.4.0.1134.139'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-source', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-source-4.4.0', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-1099-kvm', 'pkgver': '4.4.0-1099.108'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-1134-aws', 'pkgver': '4.4.0-1134.148'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-218', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-218-generic', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.4.0-218-lowlatency', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-tools-aws', 'pkgver': '4.4.0.1134.139'},
    {'osver': '16.04', 'pkgname': 'linux-tools-common', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-host', 'pkgver': '4.4.0-218.251'},
    {'osver': '16.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '4.4.0.1099.97'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-lts-xenial', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-virtual', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-utopic', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-vivid', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-wily', 'pkgver': '4.4.0.218.225'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-lts-xenial', 'pkgver': '4.4.0.218.225'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-cloud-tools-4.4.0-1134 / etc');
}
