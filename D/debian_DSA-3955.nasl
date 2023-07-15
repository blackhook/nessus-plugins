#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3955. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102791);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-3636", "CVE-2017-3641", "CVE-2017-3653");
  script_xref(name:"DSA", value:"3955");

  script_name(english:"Debian DSA-3955-1 : mariadb-10.1 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been discovered in the MariaDB database server.
The vulnerabilities are addressed by upgrading MariaDB to the new
upstream version 10.1.26. Please see the MariaDB 10.1 Release Notes
for further details :

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10124-release-
    notes/
  -
    https://mariadb.com/kb/en/mariadb/mariadb-10125-release-
    notes/

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10126-release-
    notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10124-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10124-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10125-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10125-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10126-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10126-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/mariadb-10.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3955"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mariadb-10.1 packages.

For the stable distribution (stretch), these problems have been fixed
in version 10.1.26-0+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/28");
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
if (deb_check(release:"9.0", prefix:"libmariadbclient-dev", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmariadbclient-dev-compat", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmariadbclient18", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmariadbd-dev", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmariadbd18", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-client", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-client-10.1", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-client-core-10.1", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-common", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-connect", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-cracklib-password-check", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-gssapi-client", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-gssapi-server", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-mroonga", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-oqgraph", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-spider", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-tokudb", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-server", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-server-10.1", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-server-core-10.1", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-test", reference:"10.1.26-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-test-data", reference:"10.1.26-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
