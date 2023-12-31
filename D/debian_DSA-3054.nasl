#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3054. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78589);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-5615", "CVE-2014-4274", "CVE-2014-4287", "CVE-2014-6463", "CVE-2014-6464", "CVE-2014-6469", "CVE-2014-6478", "CVE-2014-6484", "CVE-2014-6491", "CVE-2014-6494", "CVE-2014-6495", "CVE-2014-6496", "CVE-2014-6500", "CVE-2014-6505", "CVE-2014-6507", "CVE-2014-6520", "CVE-2014-6530", "CVE-2014-6551", "CVE-2014-6555", "CVE-2014-6559");
  script_bugtraq_id(56766, 69732, 70444, 70446, 70451, 70455, 70462, 70469, 70478, 70486, 70487, 70489, 70496, 70497, 70510, 70516, 70517, 70530, 70532, 70550);
  script_xref(name:"DSA", value:"3054");

  script_name(english:"Debian DSA-3054-1 : mysql-5.5 - security update");
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
version 5.5.40. Please see the MySQL 5.5 Release Notes and Oracle's
Critical Patch Update advisory for further details :

  -
    https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5
    -39.html
  -
    https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5
    -40.html

  -
    http://www.oracle.com/technetwork/topics/security/cpuoct
    2014-1972960.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=765663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-39.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-40.html"
  );
  # https://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ada40cc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/mysql-5.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2014/dsa-3054"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-5.5 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 5.5.40-0+wheezy1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"libmysqlclient-dev", reference:"5.5.40-0+wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"libmysqlclient18", reference:"5.5.40-0+wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"libmysqld-dev", reference:"5.5.40-0+wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"libmysqld-pic", reference:"5.5.40-0+wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-client", reference:"5.5.40-0+wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-client-5.5", reference:"5.5.40-0+wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-common", reference:"5.5.40-0+wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-server", reference:"5.5.40-0+wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-server-5.5", reference:"5.5.40-0+wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-server-core-5.5", reference:"5.5.40-0+wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-source-5.5", reference:"5.5.40-0+wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"mysql-testsuite-5.5", reference:"5.5.40-0+wheezy1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
