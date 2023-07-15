#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4091. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106176);
  script_version("3.5");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2018-2562", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668");
  script_xref(name:"DSA", value:"4091");

  script_name(english:"Debian DSA-4091-1 : mysql-5.5 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been discovered in the MySQL database server. The
vulnerabilities are addressed by upgrading MySQL to the new upstream
version 5.5.59, which includes additional changes. Please see the
MySQL 5.5 Release Notes and Oracle's Critical Patch Update advisory
for further details :

  -
    https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5
    -59.html
  -
    http://www.oracle.com/technetwork/security-advisory/cpuj
    an2018-3236628.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-59.html"
  );
  # https://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ee54bd8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/mysql-5.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/mysql-5.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4091"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-5.5 packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 5.5.59-0+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libmysqlclient-dev", reference:"5.5.59-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmysqlclient18", reference:"5.5.59-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmysqld-dev", reference:"5.5.59-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmysqld-pic", reference:"5.5.59-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-client", reference:"5.5.59-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-client-5.5", reference:"5.5.59-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-common", reference:"5.5.59-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-server", reference:"5.5.59-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-server-5.5", reference:"5.5.59-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-server-core-5.5", reference:"5.5.59-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-source-5.5", reference:"5.5.59-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-testsuite", reference:"5.5.59-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-testsuite-5.5", reference:"5.5.59-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
