#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2120. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49966);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-3433");
  script_bugtraq_id(43747);
  script_xref(name:"DSA", value:"2120");

  script_name(english:"Debian DSA-2120-1 : postgresql-8.3 - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tim Bunce discovered that PostgreSQL, a database server software, does
not properly separate interpreters for server-side stored procedures
which run in different security contexts. As a result, non-privileged
authenticated database users might gain additional privileges.

Note that this security update may impact intended communication
through global variables between stored procedures. It might be
necessary to convert these functions to run under the plperlu or
pltclu languages, with database superuser privileges.

This security update also includes unrelated bug fixes from PostgreSQL
8.3.12."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2010/dsa-2120"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the PostgreSQL packages.

For the stable distribution (lenny), this problem has been fixed in
version 8.3_8.3.12-0lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-8.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"5.0", prefix:"libecpg-compat3", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libecpg-dev", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libecpg6", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpgtypes3", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpq-dev", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpq5", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-8.3", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-client", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-client-8.3", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-contrib", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-contrib-8.3", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-doc", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-doc-8.3", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-plperl-8.3", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-plpython-8.3", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-pltcl-8.3", reference:"8.3.12-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-server-dev-8.3", reference:"8.3.12-0lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
