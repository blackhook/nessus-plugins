#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3446. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176729);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/06");

  script_cve_id("CVE-2023-0386", "CVE-2023-31436", "CVE-2023-32233");

  script_name(english:"Debian DLA-3446-1 : linux-5.10 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3446 advisory.

  - A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with
    capabilities was found in the Linux kernel's OverlayFS subsystem in how a user copies a capable file from
    a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges
    on the system. (CVE-2023-0386)

  - qfq_change_class in net/sched/sch_qfq.c in the Linux kernel before 6.2.13 allows an out-of-bounds write
    because lmax can exceed QFQ_MIN_LMAX. (CVE-2023-31436)

  - In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests
    can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users
    can obtain root privileges. This occurs because anonymous sets are mishandled. (CVE-2023-32233)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1035779");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux-5.10");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3446");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0386");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-31436");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32233");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux-5.10");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux-5.10 packages.

For Debian 10 buster, these problems have been fixed in version 5.10.179-1~deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32233");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.22-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.23-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.22-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.23-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.23");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-686', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-686-pae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-cloud-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-cloud-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-common', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-common-rt', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-686-pae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-686', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-686-pae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-cloud-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-cloud-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-common', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-common-rt', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-686-pae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-686', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-686-pae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-cloud-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-cloud-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-common', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-common-rt', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-686-pae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-686', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-686-pae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-cloud-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-cloud-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-common', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-common-rt', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-rt-686-pae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-rt-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-rt-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-686', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-686-pae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-cloud-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-cloud-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-common', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-common-rt', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-rt-686-pae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-rt-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-rt-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.22-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-686', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-686-pae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-cloud-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-cloud-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-common', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-common-rt', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-rt-686-pae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-rt-amd64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-rt-arm64', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.23-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-signed-template', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-signed-template', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-i386-signed-template', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-pae-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-lpae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-686-pae-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-pae-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-lpae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-686-pae-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-pae-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp-lpae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-686-pae-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-686-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-686-pae-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-686-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-armmp-lpae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-cloud-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-cloud-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-cloud-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-cloud-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-686-pae-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-686-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-686-pae-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-686-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-armmp-lpae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-cloud-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-cloud-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-cloud-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-cloud-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-686-pae-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.22-rt-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-686-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-686-pae-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-686-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-armmp-lpae', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-armmp-lpae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-cloud-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-cloud-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-cloud-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-cloud-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-rt-686-pae-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-rt-686-pae-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-rt-amd64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-rt-amd64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-rt-arm64-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-rt-arm64-unsigned', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-rt-armmp', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.23-rt-armmp-dbg', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.17', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.19', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.20', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.21', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.22', 'reference': '5.10.179-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.23', 'reference': '5.10.179-1~deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-config-5.10 / linux-doc-5.10 / linux-headers-5.10-armmp / etc');
}
