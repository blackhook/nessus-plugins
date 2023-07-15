#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1424-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111166);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-1424-1 : linux-latest-4.9 new package");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Linux 4.9 has been packaged for Debian 8 as linux-4.9. This provides a
supported upgrade path for systems that currently use kernel packages
from the 'jessie-backports' suite.

However, 'apt full-upgrade' will *not* automatically install the
updated kernel packages. You should explicitly install one of the
following metapackages first, as appropriate for your system :

linux-image-4.9-686 linux-image-4.9-686-pae linux-image-4.9-amd64
linux-image-4.9-armmp linux-image-4.9-armmp-lpae
linux-image-4.9-marvell

For example, if the command 'uname -r' currently shows
'4.9.0-0.bpo.6-amd64', you should install linux-image-4.9-amd64.

There is no need to upgrade systems using Linux 3.16, as that kernel
version will also continue to be supported in the LTS period.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/linux-latest-4.9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.9-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.9-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");
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
if (deb_check(release:"8.0", prefix:"linux-headers-4.9-686", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9-686-pae", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9-amd64", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9-armmp", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9-armmp-lpae", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9-marvell", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9-rt-686-pae", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-headers-4.9-rt-amd64", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9-686", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9-686-pae", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9-686-pae-dbg", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9-amd64", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9-amd64-dbg", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9-armmp", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9-armmp-lpae", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9-marvell", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9-rt-686-pae", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9-rt-686-pae-dbg", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9-rt-amd64", reference:"80+deb9u5~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"linux-image-4.9-rt-amd64-dbg", reference:"80+deb9u5~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
