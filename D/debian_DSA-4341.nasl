#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4341. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119040);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/31");

  script_cve_id("CVE-2017-10268", "CVE-2017-10378", "CVE-2017-15365", "CVE-2018-2562", "CVE-2018-2612", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668", "CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2766", "CVE-2018-2767", "CVE-2018-2771", "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2787", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819", "CVE-2018-3058", "CVE-2018-3063", "CVE-2018-3064", "CVE-2018-3066", "CVE-2018-3081", "CVE-2018-3143", "CVE-2018-3156", "CVE-2018-3174", "CVE-2018-3251", "CVE-2018-3282");
  script_xref(name:"DSA", value:"4341");

  script_name(english:"Debian DSA-4341-1 : mariadb-10.1 - security update");
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
upstream version 10.1.37. Please see the MariaDB 10.1 Release Notes
for further details :

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10127-release-
    notes/
  -
    https://mariadb.com/kb/en/mariadb/mariadb-10128-release-
    notes/

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10129-release-
    notes/

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10130-release-
    notes/

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10131-release-
    notes/

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10132-release-
    notes/

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10133-release-
    notes/

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10134-release-
    notes/

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10135-release-
    notes/

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10136-release-
    notes/

  -
    https://mariadb.com/kb/en/mariadb/mariadb-10137-release-
    notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=885345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=898444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=898445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=912848"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10127-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10127-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10128-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10128-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10129-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10129-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10130-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10130-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10131-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10131-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10132-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10132-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10133-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10133-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10134-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10134-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10135-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10135-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10136-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10136-release-notes/"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10137-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10137-release-notes/"
  );
  # https://security-tracker.debian.org/tracker/source-package/mariadb-10.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?708f0173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/mariadb-10.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4341"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the mariadb-10.1 packages.

For the stable distribution (stretch), these problems have been fixed
in version 10.1.37-0+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2612");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libmariadbclient-dev", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmariadbclient-dev-compat", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmariadbclient18", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmariadbd-dev", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmariadbd18", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-client", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-client-10.1", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-client-core-10.1", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-common", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-connect", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-cracklib-password-check", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-gssapi-client", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-gssapi-server", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-mroonga", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-oqgraph", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-spider", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-plugin-tokudb", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-server", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-server-10.1", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-server-core-10.1", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-test", reference:"10.1.37-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"mariadb-test-data", reference:"10.1.37-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
