#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2321-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139519);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/12");

  script_name(english:"Debian DLA-2321-1 : firmware-nonfree new upstream version");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The firmware-nonfree package has been updated to include additional
firmware that may be requested by some drivers in Linux 4.19.

Along with additional kernel packages that will be announced later,
this will provide a supported upgrade path for systems that currently
use kernel and firmware packages from the 'stretch-backports' suite.

This update is not known to fix any security issues.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/firmware-nonfree"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-adi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-amd-graphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-atheros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-bnx2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-bnx2x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-brcm80211");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-cavium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-intel-sound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-intelwimax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-ipw2x00");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-ivtv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-iwlwifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-libertas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-linux-nonfree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-misc-nonfree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-myricom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-netxen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-qlogic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-ralink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-realtek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-samsung");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-siano");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firmware-ti-connectivity");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"firmware-adi", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-amd-graphics", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-atheros", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-bnx2", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-bnx2x", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-brcm80211", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-cavium", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-intel-sound", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-intelwimax", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-ipw2x00", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-ivtv", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-iwlwifi", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-libertas", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-linux", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-linux-nonfree", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-misc-nonfree", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-myricom", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-netxen", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-qlogic", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-ralink", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-realtek", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-samsung", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-siano", reference:"20190114-2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"firmware-ti-connectivity", reference:"20190114-2~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
