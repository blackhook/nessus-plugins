#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3922. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102046);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-3635", "CVE-2017-3636", "CVE-2017-3641", "CVE-2017-3648", "CVE-2017-3651", "CVE-2017-3652", "CVE-2017-3653");
  script_xref(name:"DSA", value:"3922");

  script_name(english:"Debian DSA-3922-1 : mysql-5.5 - security update");
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
version 5.5.57, which includes additional changes, such as performance
improvements, bug fixes, new features, and possibly incompatible
changes. Please see the MySQL 5.5 Release Notes and Oracle's Critical
Patch Update advisory for further details :

  -
    https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5
    -56.html
  -
    https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5
    -57.html

  -
    http://www.oracle.com/technetwork/security-advisory/cpuj
    ul2017-3236622.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=868788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-56.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-57.html"
  );
  # https://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88deb2ba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/mysql-5.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3922"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-5.5 packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 5.5.57-0+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libmysqlclient-dev", reference:"5.5.57-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmysqlclient18", reference:"5.5.57-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmysqld-dev", reference:"5.5.57-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmysqld-pic", reference:"5.5.57-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-client", reference:"5.5.57-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-client-5.5", reference:"5.5.57-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-common", reference:"5.5.57-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-server", reference:"5.5.57-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-server-5.5", reference:"5.5.57-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-server-core-5.5", reference:"5.5.57-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-source-5.5", reference:"5.5.57-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-testsuite", reference:"5.5.57-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-testsuite-5.5", reference:"5.5.57-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
