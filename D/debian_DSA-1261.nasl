#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1261. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24359);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-0555");
  script_xref(name:"DSA", value:"1261");

  script_name(english:"Debian DSA-1261-1 : postgresql - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the PostgreSQL database performs insufficient
type checking for SQL function arguments, which might lead to denial
of service or information disclosure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1261"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the PostgreSQL packages.

For the stable distribution (sarge) this problem has been fixed in
version 7.4.7-6sarge4.

For the upcoming stable distribution (etch) this problem has been
fixed in version 8.1.7-1 of the postgresql-8.1 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libecpg-dev", reference:"7.4.7-6sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"libecpg4", reference:"7.4.7-6sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"libpgtcl", reference:"7.4.7-6sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"libpgtcl-dev", reference:"7.4.7-6sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"libpq3", reference:"7.4.7-6sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql", reference:"7.4.7-6sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-client", reference:"7.4.7-6sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-contrib", reference:"7.4.7-6sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-dev", reference:"7.4.7-6sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-doc", reference:"7.4.7-6sarge4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
