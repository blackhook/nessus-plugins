#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1317-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#
# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.

include("compat.inc");

if (description)
{
  script_id(108607);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/20  0:18:52");

  script_cve_id("CVE-2018-1000116");

  script_name(english:"Debian DLA-1317-1 : net-snmp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was a heap corruption vulnerability in
the net-snmp framework which exchanges server management information
in a network.

For Debian 7 'Wheezy', this issue has been fixed in net-snmp version
5.7.2.1+dfsg-1+deb8u1.

We recommend that you upgrade your net-snmp packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/net-snmp"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp15-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tkmib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("audit.inc");
include("debian_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"libsnmp-base", reference:"5.7.2.1+dfsg-1+deb8u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsnmp-dev", reference:"5.7.2.1+dfsg-1+deb8u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsnmp-perl", reference:"5.7.2.1+dfsg-1+deb8u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsnmp-python", reference:"5.7.2.1+dfsg-1+deb8u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsnmp15", reference:"5.7.2.1+dfsg-1+deb8u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsnmp15-dbg", reference:"5.7.2.1+dfsg-1+deb8u1")) flag++;
if (deb_check(release:"7.0", prefix:"snmp", reference:"5.7.2.1+dfsg-1+deb8u1")) flag++;
if (deb_check(release:"7.0", prefix:"snmpd", reference:"5.7.2.1+dfsg-1+deb8u1")) flag++;
if (deb_check(release:"7.0", prefix:"tkmib", reference:"5.7.2.1+dfsg-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
