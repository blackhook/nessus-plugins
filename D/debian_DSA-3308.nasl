#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3308. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84836);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-2582", "CVE-2015-2620", "CVE-2015-2643", "CVE-2015-2648", "CVE-2015-4737", "CVE-2015-4752");
  script_bugtraq_id(75751, 75802, 75822, 75830, 75837, 75849);
  script_xref(name:"DSA", value:"3308");

  script_name(english:"Debian DSA-3308-1 : mysql-5.5 - security update");
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
version 5.5.44. Please see the MySQL 5.5 Release Notes and Oracle's
Critical Patch Update advisory for further details :

  -
    https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5
    -44.html
  -
    http://www.oracle.com/technetwork/topics/security/cpujul
    2015-2367936.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=792445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-44.html"
  );
  # https://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2b7623c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/mysql-5.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/mysql-5.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3308"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-5.5 packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 5.5.44-0+deb7u1.

For the stable distribution (jessie), these problems have been fixed
in version 5.5.44-0+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"libmysqlclient-dev", reference:"5.5.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmysqlclient18", reference:"5.5.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmysqld-dev", reference:"5.5.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmysqld-pic", reference:"5.5.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-client", reference:"5.5.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-client-5.5", reference:"5.5.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-common", reference:"5.5.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-server", reference:"5.5.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-server-5.5", reference:"5.5.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-server-core-5.5", reference:"5.5.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-source-5.5", reference:"5.5.44-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-testsuite-5.5", reference:"5.5.44-0+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmysqlclient-dev", reference:"5.5.44-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmysqlclient18", reference:"5.5.44-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmysqld-dev", reference:"5.5.44-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libmysqld-pic", reference:"5.5.44-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-client", reference:"5.5.44-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-client-5.5", reference:"5.5.44-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-common", reference:"5.5.44-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-server", reference:"5.5.44-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-server-5.5", reference:"5.5.44-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-server-core-5.5", reference:"5.5.44-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-source-5.5", reference:"5.5.44-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-testsuite", reference:"5.5.44-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mysql-testsuite-5.5", reference:"5.5.44-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
