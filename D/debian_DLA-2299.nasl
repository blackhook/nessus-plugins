#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2299-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139207);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/31");

  script_name(english:"Debian DLA-2299-1 : net-snmp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A privilege escalation vulnerability vulnerability was discovered in
Net-SNMP, a set of tools for collecting and organising information
about devices on computer networks.

Upstream notes that :

  - It is still possible to enable this MIB via the

    --with-mib-modules configure option.

  - Another MIB that provides similar functionality, namely
    ucd-snmp/extensible, is disabled by default.

  - The security risk of ucd-snmp/pass and
    ucd-snmp/pass_persist is lower since these modules only
    introduce a security risk if the invoked scripts are
    exploitable.

For Debian 9 'Stretch', this issue has been fixed in net-snmp version
5.7.3+dfsg-1.7+deb9u2.

We recommend that you upgrade your net-snmp packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/net-snmp"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp30-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-netsnmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tkmib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");
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
if (deb_check(release:"9.0", prefix:"libsnmp-base", reference:"5.7.3+dfsg-1.7+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsnmp-dev", reference:"5.7.3+dfsg-1.7+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsnmp-perl", reference:"5.7.3+dfsg-1.7+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsnmp30", reference:"5.7.3+dfsg-1.7+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsnmp30-dbg", reference:"5.7.3+dfsg-1.7+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python-netsnmp", reference:"5.7.3+dfsg-1.7+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"snmp", reference:"5.7.3+dfsg-1.7+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"snmpd", reference:"5.7.3+dfsg-1.7+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"snmptrapd", reference:"5.7.3+dfsg-1.7+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"tkmib", reference:"5.7.3+dfsg-1.7+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
