#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-964-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100575);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-9932", "CVE-2017-7995", "CVE-2017-8903", "CVE-2017-8904", "CVE-2017-8905");

  script_name(english:"Debian DLA-964-1 : xen security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the Xen hypervisor.
The Common Vulnerabilities and Exposures project identifies the
following problems :

CVE-2016-9932 (XSA-200)

CMPXCHG8B emulation allows local HVM guest OS users to obtain
sensitive information from host stack memory.

CVE-2017-7995

Description Xen checks access permissions to MMIO ranges only after
accessing them, allowing host PCI device space memory reads.

CVE-2017-8903 (XSA-213)

Xen mishandles page tables after an IRET hypercall which can lead to
arbitrary code execution on the host OS. The vulnerability is only
exposed to 64-bit PV guests.

CVE-2017-8904 (XSA-214)

Xen mishandles the 'contains segment descriptors' property during
GNTTABOP_transfer. This might allow PV guest OS users to execute
arbitrary code on the host OS.

CVE-2017-8905 (XSA-215)

Xen mishandles a failsafe callback which might allow PV guest OS users
to execute arbitrary code on the host OS.

For Debian 7 'Wheezy', these problems have been fixed in version
4.1.6.lts1-8.

We recommend that you upgrade your xen packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/06/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xen"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxen-ocaml-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxenstore3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-docs-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.1-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-hypervisor-4.1-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-system-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils-4.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen-utils-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xenstore-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libxen-4.1", reference:"4.1.6.lts1-8")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-dev", reference:"4.1.6.lts1-8")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml", reference:"4.1.6.lts1-8")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml-dev", reference:"4.1.6.lts1-8")) flag++;
if (deb_check(release:"7.0", prefix:"libxenstore3.0", reference:"4.1.6.lts1-8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-docs-4.1", reference:"4.1.6.lts1-8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-amd64", reference:"4.1.6.lts1-8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-i386", reference:"4.1.6.lts1-8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-amd64", reference:"4.1.6.lts1-8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-i386", reference:"4.1.6.lts1-8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-4.1", reference:"4.1.6.lts1-8")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-common", reference:"4.1.6.lts1-8")) flag++;
if (deb_check(release:"7.0", prefix:"xenstore-utils", reference:"4.1.6.lts1-8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
