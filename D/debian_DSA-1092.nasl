#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1092. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22634);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-2753");
  script_bugtraq_id(18219);
  script_xref(name:"DSA", value:"1092");

  script_name(english:"Debian DSA-1092-1 : mysql-dfsg-4.1 - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Josh Berkus and Tom Lane discovered that MySQL 4.1, a popular SQL
database, incorrectly parses a string escaped with mysql_real_escape()
which could lead to SQL injection. This problem does only exist in
versions 4.1 and 5.0."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1092"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql packages.

The old stable distribution (woody) is not affected by this problem.

For the stable distribution (sarge) this problem has been fixed in
version 4.1.11a-4sarge4.

Version 4.0 in the stable distribution (sarge) is also not affected by
this problem."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg-4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libmysqlclient14", reference:"4.1.11a-4sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"libmysqlclient14-dev", reference:"4.1.11a-4sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-client-4.1", reference:"4.1.11a-4sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-common-4.1", reference:"4.1.11a-4sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-server-4.1", reference:"4.1.11a-4sarge4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
