#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1270-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106633);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2016-9603", "CVE-2016-9637", "CVE-2017-2620");
  script_xref(name:"IAVB", value:"2017-B-0024-S");

  script_name(english:"Debian DLA-1270-1 : xen security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the Xen hypervisor,
which could result in privilege escalation.

For Debian 7 'Wheezy', these problems have been fixed in version
4.1.6.lts1-12.

We recommend that you upgrade your xen packages.

Please note that CVE-2017-15590 (XSA-237) will *not* be fixed in
wheezy as the patches are too intrusive to backport. The vulnerability
can be mitigated by not passing through physical devices to untrusted
guests. More information can be found on
https://xenbits.xen.org/xsa/advisory-237.html

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/02/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://xenbits.xen.org/xsa/advisory-237.html"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"libxen-4.1", reference:"4.1.6.lts1-12")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-dev", reference:"4.1.6.lts1-12")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml", reference:"4.1.6.lts1-12")) flag++;
if (deb_check(release:"7.0", prefix:"libxen-ocaml-dev", reference:"4.1.6.lts1-12")) flag++;
if (deb_check(release:"7.0", prefix:"libxenstore3.0", reference:"4.1.6.lts1-12")) flag++;
if (deb_check(release:"7.0", prefix:"xen-docs-4.1", reference:"4.1.6.lts1-12")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-amd64", reference:"4.1.6.lts1-12")) flag++;
if (deb_check(release:"7.0", prefix:"xen-hypervisor-4.1-i386", reference:"4.1.6.lts1-12")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-amd64", reference:"4.1.6.lts1-12")) flag++;
if (deb_check(release:"7.0", prefix:"xen-system-i386", reference:"4.1.6.lts1-12")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-4.1", reference:"4.1.6.lts1-12")) flag++;
if (deb_check(release:"7.0", prefix:"xen-utils-common", reference:"4.1.6.lts1-12")) flag++;
if (deb_check(release:"7.0", prefix:"xenstore-utils", reference:"4.1.6.lts1-12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
