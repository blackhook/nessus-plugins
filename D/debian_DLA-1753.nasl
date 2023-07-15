#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1753-3. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123834);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-1753-3 : proftpd-dfsg regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The update of proftpd-dfsg issued as DLA-1753-1 caused a regression
when the creation of a directory failed during sftp transfer. The sftp
session would be terminated instead of failing gracefully due to a
non-existing debug logging function.

For Debian 8 'Jessie', this problem has been fixed in version
1.3.5e+r1.3.5-2+deb8u2.

We recommend that you upgrade your proftpd-dfsg packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/05/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/proftpd-dfsg"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-mod-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/09");
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
if (deb_check(release:"8.0", prefix:"proftpd-basic", reference:"1.3.5e+r1.3.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"proftpd-dev", reference:"1.3.5e+r1.3.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"proftpd-doc", reference:"1.3.5e+r1.3.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"proftpd-mod-geoip", reference:"1.3.5e+r1.3.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"proftpd-mod-ldap", reference:"1.3.5e+r1.3.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"proftpd-mod-mysql", reference:"1.3.5e+r1.3.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"proftpd-mod-odbc", reference:"1.3.5e+r1.3.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"proftpd-mod-pgsql", reference:"1.3.5e+r1.3.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"proftpd-mod-sqlite", reference:"1.3.5e+r1.3.5-2+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
