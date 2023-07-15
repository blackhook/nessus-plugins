##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5135-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(154974);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2021-3759");
  script_xref(name:"USN", value:"5135-1");

  script_name(english:"Ubuntu 20.04 LTS / 21.04 / 21.10 : Linux kernel vulnerability (USN-5135-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-5135-1 advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's
self-reported version number.

  - A memory overflow vulnerability was found in the Linux kernel's ipc functionality of the memcg subsystem,
    in the way a user calls the semget function multiple times, creating semaphores. This flaw allows a local
    user to starve the resources, causing a denial of service. The highest threat from this vulnerability is
    to system availability. (CVE-2021-3759)");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5135-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3759");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.11-cloud-tools-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.11-headers-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-5.11-tools-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-5.13.0-1006");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-5.13.0-1006");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-5.13.0-1006");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.11-cloud-tools-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.11-headers-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-5.11-tools-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-5.13.0-1007");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-5.13.0-1007");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-5.13.0-1007");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1019-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1021-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1021-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1022-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1022-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-1022-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-40-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-40-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-40-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.11.0-40-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1005-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1006-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1006-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1007-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1009-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1010-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1010-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1019-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-21-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-21-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-21-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-21-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-1021-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-40-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.11.0-40-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-1006-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-1007-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-21-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-21-lowlatency");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.11-headers-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-5.11-tools-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-5.13.0-1006");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-5.13.0-1006");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1019-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1021-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1021-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1022-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1022-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-1022-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-40-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-40-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-40-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.11.0-40-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1005-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1006-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1006-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1007-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1009-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1010-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1010-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1019-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-21-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-21-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-21-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-21-lowlatency");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-cloud-tools-5.11.0-40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-headers-5.11.0-40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-source-5.11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-tools-5.11.0-40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-5.11-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1019-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1021-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1021-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1022-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1022-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1022-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-40-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-40-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-40-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-40-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1005-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1006-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1006-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1007-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1009-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1010-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1010-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1019-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-21-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-21-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-21-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-21-lowlatency");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1019-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1021-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1021-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-1022-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-40-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-40-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.11.0-40-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1005-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1006-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1007-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1009-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1019-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-21-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-21-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-21-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-5.11.0-1019");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-5.13.0-1005");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-5.11.0-1019");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-5.13.0-1005");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1019-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1021-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1021-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1022-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1022-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-1022-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-40-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-40-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-40-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.11.0-40-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1005-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1006-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1006-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1007-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1009-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1010-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1010-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1019-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-21-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-21-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-21-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-21-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1021-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1021-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-1022-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.11.0-40-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1006-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1006-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1007-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1009-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1010-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1010-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-21-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.13-headers-5.13.0-1019");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.13-tools-5.13.0-1019");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.13-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.11-headers-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-5.11-tools-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-5.13.0-1009");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-5.11.0-1021");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-5.13.0-1009");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-headers-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-headers-5.13.0-1010");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-tools-5.11.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-tools-5.13.0-1010");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.13.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1019-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1021-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1021-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1021-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1022-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1022-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-1022-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-40-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-40-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-40-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.11.0-40-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1005-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1006-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1006-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1007-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1009-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1010-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1010-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1019-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-21-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-21-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-21-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-21-lowlatency");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04c");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(20\.04|21\.04|21\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 21.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'linux-aws', 'pkgver': '5.11.0.1021.22~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-aws-5.11-cloud-tools-5.11.0-1021', 'pkgver': '5.11.0-1021.22~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-aws-5.11-headers-5.11.0-1021', 'pkgver': '5.11.0-1021.22~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-aws-5.11-tools-5.11.0-1021', 'pkgver': '5.11.0-1021.22~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-aws-edge', 'pkgver': '5.11.0.1021.22~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-azure', 'pkgver': '5.11.0.1021.22~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-azure-5.11-cloud-tools-5.11.0-1021', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-azure-5.11-headers-5.11.0-1021', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-azure-5.11-tools-5.11.0-1021', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-azure-edge', 'pkgver': '5.11.0.1021.22~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-40-generic', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-40-generic-64k', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-40-generic-lpae', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.13.0-1019-oem', 'pkgver': '5.13.0-1019.23'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.11.0-40-generic', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.11.0.1021.22~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-azure-edge', 'pkgver': '5.11.0.1021.22~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-gcp', 'pkgver': '5.11.0.1022.24~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-5.11-headers-5.11.0-1022', 'pkgver': '5.11.0-1022.24~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-5.11-tools-5.11.0-1022', 'pkgver': '5.11.0-1022.24~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-gcp-edge', 'pkgver': '5.11.0.1022.24~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-40-generic', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-40-generic-64k', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-40-generic-lpae', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.13.0-1019-oem', 'pkgver': '5.13.0-1019.23'},
    {'osver': '20.04', 'pkgname': 'linux-headers-aws', 'pkgver': '5.11.0.1021.22~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-headers-aws-edge', 'pkgver': '5.11.0.1021.22~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.11.0.1021.22~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-headers-azure-edge', 'pkgver': '5.11.0.1021.22~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.11.0.1022.24~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-headers-gcp-edge', 'pkgver': '5.11.0.1022.24~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-20.04c', 'pkgver': '5.13.0.1019.23'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.11.0.1021.22~20.04.14'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oracle-edge', 'pkgver': '5.11.0.1021.22~20.04.14'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-cloud-tools-5.11.0-40', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-cloud-tools-common', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-headers-5.11.0-40', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-source-5.11.0', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-tools-5.11.0-40', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-tools-common', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-hwe-5.11-tools-host', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-40-generic', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-40-generic-64k', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-40-generic-lpae', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.13.0-1019-oem', 'pkgver': '5.13.0-1019.23'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.11.0.1021.22~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws-edge', 'pkgver': '5.11.0.1021.22~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.11.0.1021.22~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '5.11.0.1021.22~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.11.0.1022.24~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-image-gcp-edge', 'pkgver': '5.11.0.1022.24~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04c', 'pkgver': '5.13.0.1019.23'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.11.0.1021.22~20.04.14'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle-edge', 'pkgver': '5.11.0.1021.22~20.04.14'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-40-generic', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-40-generic-64k', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.13.0-1019-oem', 'pkgver': '5.13.0-1019.23'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-40-generic', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-40-generic-64k', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-40-generic-lpae', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.13.0-1019-oem', 'pkgver': '5.13.0-1019.23'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.11.0-40-generic', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.11.0.1021.22~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-aws-edge', 'pkgver': '5.11.0.1021.22~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.11.0.1021.22~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-azure-edge', 'pkgver': '5.11.0.1021.22~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.11.0.1022.24~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-gcp-edge', 'pkgver': '5.11.0.1022.24~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-oem-20.04c', 'pkgver': '5.13.0.1019.23'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.13-headers-5.13.0-1019', 'pkgver': '5.13.0-1019.23'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.13-tools-5.13.0-1019', 'pkgver': '5.13.0-1019.23'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.13-tools-host', 'pkgver': '5.13.0-1019.23'},
    {'osver': '20.04', 'pkgname': 'linux-oracle', 'pkgver': '5.11.0.1021.22~20.04.14'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-5.11-headers-5.11.0-1021', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-5.11-tools-5.11.0-1021', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-oracle-edge', 'pkgver': '5.11.0.1021.22~20.04.14'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-40-generic', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-40-generic-64k', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-40-generic-lpae', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44~20.04.2'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.13.0-1019-oem', 'pkgver': '5.13.0-1019.23'},
    {'osver': '20.04', 'pkgname': 'linux-tools-aws', 'pkgver': '5.11.0.1021.22~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-tools-aws-edge', 'pkgver': '5.11.0.1021.22~20.04.20'},
    {'osver': '20.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.11.0.1021.22~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-tools-azure-edge', 'pkgver': '5.11.0.1021.22~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.11.0.1022.24~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-tools-gcp-edge', 'pkgver': '5.11.0.1022.24~20.04.21'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-20.04c', 'pkgver': '5.13.0.1019.23'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.11.0.1021.22~20.04.14'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oracle-edge', 'pkgver': '5.11.0.1021.22~20.04.14'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.11.0.40.44~20.04.18'},
    {'osver': '21.04', 'pkgname': 'linux-aws', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-aws-cloud-tools-5.11.0-1021', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-aws-headers-5.11.0-1021', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-aws-tools-5.11.0-1021', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-azure', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-azure-cloud-tools-5.11.0-1021', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-azure-headers-5.11.0-1021', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-azure-tools-5.11.0-1021', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1019-kvm', 'pkgver': '5.11.0-1019.21'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1022-raspi', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-1022-raspi-nolpae', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-40-generic', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-40-generic-64k', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-40-generic-lpae', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-buildinfo-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-40', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-40-generic', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-crashdump', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-gcp', 'pkgver': '5.11.0.1022.22'},
    {'osver': '21.04', 'pkgname': 'linux-gcp-headers-5.11.0-1022', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-gcp-tools-5.11.0-1022', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-generic', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-generic-64k', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-generic-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-gke', 'pkgver': '5.11.0.1022.22'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1019-kvm', 'pkgver': '5.11.0-1019.21'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1022-raspi', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-1022-raspi-nolpae', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-40', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-40-generic', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-40-generic-64k', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-40-generic-lpae', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-headers-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-headers-aws', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-headers-azure', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.11.0.1022.22'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-64k', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-gke', 'pkgver': '5.11.0.1022.22'},
    {'osver': '21.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '5.11.0.1019.20'},
    {'osver': '21.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-oem-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-headers-raspi', 'pkgver': '5.11.0.1022.20'},
    {'osver': '21.04', 'pkgname': 'linux-headers-raspi-nolpae', 'pkgver': '5.11.0.1022.20'},
    {'osver': '21.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-headers-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1019-kvm', 'pkgver': '5.11.0-1019.21'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1022-raspi', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-1022-raspi-nolpae', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-40-generic', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-40-generic-64k', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-40-generic-lpae', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-image-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-extra-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.11.0.1022.22'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-gke', 'pkgver': '5.11.0.1022.22'},
    {'osver': '21.04', 'pkgname': 'linux-image-kvm', 'pkgver': '5.11.0.1019.20'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-image-raspi', 'pkgver': '5.11.0.1022.20'},
    {'osver': '21.04', 'pkgname': 'linux-image-raspi-nolpae', 'pkgver': '5.11.0.1022.20'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-1019-kvm', 'pkgver': '5.11.0-1019.21'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-40-generic', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-40-generic-64k', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-image-unsigned-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-kvm', 'pkgver': '5.11.0.1019.20'},
    {'osver': '21.04', 'pkgname': 'linux-kvm-headers-5.11.0-1019', 'pkgver': '5.11.0-1019.21'},
    {'osver': '21.04', 'pkgname': 'linux-kvm-tools-5.11.0-1019', 'pkgver': '5.11.0-1019.21'},
    {'osver': '21.04', 'pkgname': 'linux-libc-dev', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-lowlatency', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1019-kvm', 'pkgver': '5.11.0-1019.21'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1022-raspi', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-1022-raspi-nolpae', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-40-generic', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-40-generic-64k', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-40-generic-lpae', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-modules-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-5.11.0-40-generic', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.11.0.1022.22'},
    {'osver': '21.04', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '5.11.0.1022.22'},
    {'osver': '21.04', 'pkgname': 'linux-oem-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-oracle', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-oracle-headers-5.11.0-1021', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-oracle-tools-5.11.0-1021', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-raspi', 'pkgver': '5.11.0.1022.20'},
    {'osver': '21.04', 'pkgname': 'linux-raspi-headers-5.11.0-1022', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-raspi-nolpae', 'pkgver': '5.11.0.1022.20'},
    {'osver': '21.04', 'pkgname': 'linux-raspi-tools-5.11.0-1022', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-source', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-source-5.11.0', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1019-kvm', 'pkgver': '5.11.0-1019.21'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1021-aws', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1021-azure', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1021-oracle', 'pkgver': '5.11.0-1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1022-gcp', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1022-raspi', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-1022-raspi-nolpae', 'pkgver': '5.11.0-1022.24'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-40', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-40-generic', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-40-generic-64k', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-40-generic-lpae', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-tools-5.11.0-40-lowlatency', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-tools-aws', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-tools-azure', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-tools-common', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.11.0.1022.22'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-64k', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-64k-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-gke', 'pkgver': '5.11.0.1022.22'},
    {'osver': '21.04', 'pkgname': 'linux-tools-host', 'pkgver': '5.11.0-40.44'},
    {'osver': '21.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '5.11.0.1019.20'},
    {'osver': '21.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-oem-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.11.0.1021.22'},
    {'osver': '21.04', 'pkgname': 'linux-tools-raspi', 'pkgver': '5.11.0.1022.20'},
    {'osver': '21.04', 'pkgname': 'linux-tools-raspi-nolpae', 'pkgver': '5.11.0.1022.20'},
    {'osver': '21.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-tools-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-virtual', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.04', 'pkgname': 'linux-virtual-hwe-20.04-edge', 'pkgver': '5.11.0.40.41'},
    {'osver': '21.10', 'pkgname': 'linux-aws', 'pkgver': '5.13.0.1006.8'},
    {'osver': '21.10', 'pkgname': 'linux-aws-cloud-tools-5.13.0-1006', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-aws-headers-5.13.0-1006', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-aws-tools-5.13.0-1006', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-azure', 'pkgver': '5.13.0.1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-azure-cloud-tools-5.13.0-1007', 'pkgver': '5.13.0-1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-azure-headers-5.13.0-1007', 'pkgver': '5.13.0-1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-azure-tools-5.13.0-1007', 'pkgver': '5.13.0-1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1005-kvm', 'pkgver': '5.13.0-1005.5'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1006-aws', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1006-gcp', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1007-azure', 'pkgver': '5.13.0-1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1009-oracle', 'pkgver': '5.13.0-1009.11'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1010-raspi', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-1010-raspi-nolpae', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-21-generic', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-21-generic-64k', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-21-generic-lpae', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-buildinfo-5.13.0-21-lowlatency', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-1006-aws', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-1007-azure', 'pkgver': '5.13.0-1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-21', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-21-generic', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-5.13.0-21-lowlatency', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '5.13.0.1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-generic-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-cloud-tools-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-crashdump', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-gcp', 'pkgver': '5.13.0.1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-gcp-headers-5.13.0-1006', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-gcp-tools-5.13.0-1006', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-generic', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-generic-64k', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-generic-64k-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-generic-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-generic-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-gke', 'pkgver': '5.13.0.1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1005-kvm', 'pkgver': '5.13.0-1005.5'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1006-aws', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1006-gcp', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1007-azure', 'pkgver': '5.13.0-1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1009-oracle', 'pkgver': '5.13.0-1009.11'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1010-raspi', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-1010-raspi-nolpae', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-21', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-21-generic', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-21-generic-64k', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-21-generic-lpae', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-headers-5.13.0-21-lowlatency', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-headers-aws', 'pkgver': '5.13.0.1006.8'},
    {'osver': '21.10', 'pkgname': 'linux-headers-azure', 'pkgver': '5.13.0.1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-headers-gcp', 'pkgver': '5.13.0.1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-64k', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-64k-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-gke', 'pkgver': '5.13.0.1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-headers-kvm', 'pkgver': '5.13.0.1005.5'},
    {'osver': '21.10', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-lowlatency-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-oem-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-oracle', 'pkgver': '5.13.0.1009.11'},
    {'osver': '21.10', 'pkgname': 'linux-headers-raspi', 'pkgver': '5.13.0.1010.16'},
    {'osver': '21.10', 'pkgname': 'linux-headers-raspi-nolpae', 'pkgver': '5.13.0.1010.16'},
    {'osver': '21.10', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-virtual-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-headers-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1005-kvm', 'pkgver': '5.13.0-1005.5'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1006-aws', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1006-gcp', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1007-azure', 'pkgver': '5.13.0-1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1009-oracle', 'pkgver': '5.13.0-1009.11'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1010-raspi', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-1010-raspi-nolpae', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-21-generic', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-21-generic-64k', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-21-generic-lpae', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-image-5.13.0-21-lowlatency', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-image-aws', 'pkgver': '5.13.0.1006.8'},
    {'osver': '21.10', 'pkgname': 'linux-image-azure', 'pkgver': '5.13.0.1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-extra-virtual-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-extra-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-gcp', 'pkgver': '5.13.0.1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-gke', 'pkgver': '5.13.0.1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-image-kvm', 'pkgver': '5.13.0.1005.5'},
    {'osver': '21.10', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-oracle', 'pkgver': '5.13.0.1009.11'},
    {'osver': '21.10', 'pkgname': 'linux-image-raspi', 'pkgver': '5.13.0.1010.16'},
    {'osver': '21.10', 'pkgname': 'linux-image-raspi-nolpae', 'pkgver': '5.13.0.1010.16'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1005-kvm', 'pkgver': '5.13.0-1005.5'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1006-gcp', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1007-azure', 'pkgver': '5.13.0-1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-1009-oracle', 'pkgver': '5.13.0-1009.11'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-21-generic', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-21-generic-64k', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-image-unsigned-5.13.0-21-lowlatency', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-image-virtual', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-kvm', 'pkgver': '5.13.0.1005.5'},
    {'osver': '21.10', 'pkgname': 'linux-kvm-headers-5.13.0-1005', 'pkgver': '5.13.0-1005.5'},
    {'osver': '21.10', 'pkgname': 'linux-kvm-tools-5.13.0-1005', 'pkgver': '5.13.0-1005.5'},
    {'osver': '21.10', 'pkgname': 'linux-libc-dev', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-lowlatency', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-lowlatency-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1005-kvm', 'pkgver': '5.13.0-1005.5'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1006-aws', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1006-gcp', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1007-azure', 'pkgver': '5.13.0-1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1009-oracle', 'pkgver': '5.13.0-1009.11'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1010-raspi', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-1010-raspi-nolpae', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-21-generic', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-21-generic-64k', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-21-generic-lpae', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-modules-5.13.0-21-lowlatency', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1006-aws', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1006-gcp', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1007-azure', 'pkgver': '5.13.0-1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1009-oracle', 'pkgver': '5.13.0-1009.11'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1010-raspi', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-1010-raspi-nolpae', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-5.13.0-21-generic', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-aws', 'pkgver': '5.13.0.1006.8'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '5.13.0.1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '5.13.0.1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '5.13.0.1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-raspi', 'pkgver': '5.13.0.1010.16'},
    {'osver': '21.10', 'pkgname': 'linux-modules-extra-raspi-nolpae', 'pkgver': '5.13.0.1010.16'},
    {'osver': '21.10', 'pkgname': 'linux-oem-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-oracle', 'pkgver': '5.13.0.1009.11'},
    {'osver': '21.10', 'pkgname': 'linux-oracle-headers-5.13.0-1009', 'pkgver': '5.13.0-1009.11'},
    {'osver': '21.10', 'pkgname': 'linux-oracle-tools-5.13.0-1009', 'pkgver': '5.13.0-1009.11'},
    {'osver': '21.10', 'pkgname': 'linux-raspi', 'pkgver': '5.13.0.1010.16'},
    {'osver': '21.10', 'pkgname': 'linux-raspi-headers-5.13.0-1010', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-raspi-nolpae', 'pkgver': '5.13.0.1010.16'},
    {'osver': '21.10', 'pkgname': 'linux-raspi-tools-5.13.0-1010', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-source', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-source-5.13.0', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1005-kvm', 'pkgver': '5.13.0-1005.5'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1006-aws', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1006-gcp', 'pkgver': '5.13.0-1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1007-azure', 'pkgver': '5.13.0-1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1009-oracle', 'pkgver': '5.13.0-1009.11'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1010-raspi', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-1010-raspi-nolpae', 'pkgver': '5.13.0-1010.12'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-21', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-21-generic', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-21-generic-64k', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-21-generic-lpae', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-tools-5.13.0-21-lowlatency', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-tools-aws', 'pkgver': '5.13.0.1006.8'},
    {'osver': '21.10', 'pkgname': 'linux-tools-azure', 'pkgver': '5.13.0.1007.8'},
    {'osver': '21.10', 'pkgname': 'linux-tools-common', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-tools-gcp', 'pkgver': '5.13.0.1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-64k', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-64k-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-64k-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-generic-lpae-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-gke', 'pkgver': '5.13.0.1006.7'},
    {'osver': '21.10', 'pkgname': 'linux-tools-host', 'pkgver': '5.13.0-21.21'},
    {'osver': '21.10', 'pkgname': 'linux-tools-kvm', 'pkgver': '5.13.0.1005.5'},
    {'osver': '21.10', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-lowlatency-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-lowlatency-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-oem-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-oracle', 'pkgver': '5.13.0.1009.11'},
    {'osver': '21.10', 'pkgname': 'linux-tools-raspi', 'pkgver': '5.13.0.1010.16'},
    {'osver': '21.10', 'pkgname': 'linux-tools-raspi-nolpae', 'pkgver': '5.13.0.1010.16'},
    {'osver': '21.10', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-virtual-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-tools-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-virtual', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-virtual-hwe-20.04', 'pkgver': '5.13.0.21.32'},
    {'osver': '21.10', 'pkgname': 'linux-virtual-hwe-20.04-edge', 'pkgver': '5.13.0.21.32'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-aws / linux-aws-5.11-cloud-tools-5.11.0-1021 / etc');
}
