#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1990-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130979);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-11135");

  script_name(english:"Debian DLA-1990-1 : linux-4.9 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service, or information
leak.

CVE-2018-12207

It was discovered that on Intel CPUs supporting hardware
virtualisation with Extended Page Tables (EPT), a guest VM may
manipulate the memory management hardware to cause a Machine Check
Error (MCE) and denial of service (hang or crash).

The guest triggers this error by changing page tables
without a TLB flush, so that both 4 KB and 2 MB entries for
the same virtual address are loaded into the instruction TLB
(iTLB). This update implements a mitigation in KVM that
prevents guest VMs from loading 2 MB entries into the iTLB.
This will reduce performance of guest VMs.

Further information on the mitigation can be found at
<https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/
multihit.html> or in the linux-doc-4.9 package.

Intel's explanation of the issue can be found at
<https://software.intel.com/security-software-guidance/insig
hts/deep-dive-machine-check-error-avoidance-page-size-change
-0>;.

CVE-2019-0154

Intel discovered that on their 8th and 9th generation GPUs, reading
certain registers while the GPU is in a low-power state can cause a
system hang. A local user permitted to use the GPU can use this for
denial of service.

This update mitigates the issue through changes to the i915
driver.

The affected chips (gen8 and gen9) are listed at
<https://en.wikipedia.org/wiki/List_of_Intel_graphics_proces
sing_units#Gen8>;.

CVE-2019-0155

Intel discovered that their 9th generation and newer GPUs are missing
a security check in the Blitter Command Streamer (BCS). A local user
permitted to use the GPU could use this to access any memory that the
GPU has access to, which could result in a denial of service (memory
corruption or crash), a leak of sensitive information, or privilege
escalation.

This update mitigates the issue by adding the security check
to the i915 driver.

The affected chips (gen9 onward) are listed at
<https://en.wikipedia.org/wiki/List_of_Intel_graphics_proces
sing_units#Gen9>;.

CVE-2019-11135

It was discovered that on Intel CPUs supporting transactional memory
(TSX), a transaction that is going to be aborted may continue to
execute speculatively, reading sensitive data from internal buffers
and leaking it through dependent operations. Intel calls this 'TSX
Asynchronous Abort' (TAA).

For CPUs affected by the previously published
Microarchitectural Data Sampling (MDS) issues
(CVE-2018-12126, CVE-2018-12127, CVE-2018-12130,
CVE-2019-11091), the existing mitigation also mitigates this
issue.

For processors that are vulnerable to TAA but not MDS, this
update disables TSX by default. This mitigation requires
updated CPU microcode. An updated intel-microcode package
(only available in Debian non-free) will be provided via a
future DLA. The updated CPU microcode may also be available
as part of a system firmware ('BIOS') update.

Further information on the mitigation can be found at
<https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/
tsx_async_abort.html> or in the linux-doc-4.9 package.

Intel's explanation of the issue can be found at
<https://software.intel.com/security-software-guidance/insig
hts/deep-dive-intel-transactional-synchronization-extensions
-intel-tsx-asynchronous-abort>;.

For Debian 8 'Jessie', these problems have been fixed in version
4.9.189-3+deb9u2~deb8u1.

We recommend that you upgrade your linux-4.9 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  # https://en.wikipedia.org/wiki/List_of_Intel_graphics_processing_units#Gen8
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aac5629f"
  );
  # https://en.wikipedia.org/wiki/List_of_Intel_graphics_processing_units#Gen9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09b1ea0a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/11/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux-4.9"
  );
  # https://software.intel.com/security-software-guidance/insights/deep-dive-intel-transactional-synchronization-extensions-intel-tsx-asynchronous-abort
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?900f812f"
  );
  # https://software.intel.com/security-software-guidance/insights/deep-dive-machine-check-error-avoidance-page-size-change-0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f69e143"
  );
  # https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/multihit.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?131c0984"
  );
  # https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/tsx_async_abort.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f68ddac1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-4.9-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9.0-0.bpo.7-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9.0-0.bpo.7-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-manual-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.9.0-0.bpo.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"linux-compiler-gcc-4.9-arm", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-doc-4.9", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-686", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-686-pae", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-amd64", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-armel", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-armhf", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-all-i386", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-amd64", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-armmp", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-armmp-lpae", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-common", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-common-rt", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-marvell", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-rt-686-pae", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9.0-0.bpo.7-rt-amd64", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686-pae", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-686-pae-dbg", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-amd64", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-amd64-dbg", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-armmp", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-armmp-lpae", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-marvell", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-686-pae", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-amd64", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9.0-0.bpo.7-rt-amd64-dbg", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-kbuild-4.9", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-manual-4.9", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-perf-4.9", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-source-4.9", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-support-4.9.0-0.bpo.7", reference:"4.9.189-3+deb9u2~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
