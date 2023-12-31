#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1311. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25555);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-2138");
  script_xref(name:"DSA", value:"1311");

  script_name(english:"Debian DSA-1311-1 : postgresql-7.4 - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the PostgreSQL database performs insufficient
validation of variables passed to privileged SQL statement
called'security definers', which could lead to SQL privilege
escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2007/dsa-1311"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the PostgreSQL packages.

For the oldstable distribution (sarge) this problem has been fixed in
version 7.4.7-6sarge5. A powerpc build is not yet available due to
problems with the build host. It will be provided later.

For the stable distribution (etch) this problem has been fixed in
version 7.4.17-0etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"3.1", prefix:"libecpg-dev", reference:"7.4.7-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libecpg4", reference:"7.4.7-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libpgtcl", reference:"7.4.7-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libpgtcl-dev", reference:"7.4.7-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"libpq3", reference:"7.4.7-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql", reference:"7.4.7-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-client", reference:"7.4.7-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-contrib", reference:"7.4.7-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-dev", reference:"7.4.7-6sarge5")) flag++;
if (deb_check(release:"3.1", prefix:"postgresql-doc", reference:"7.4.7-6sarge5")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-7.4", reference:"7.4.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-client-7.4", reference:"7.4.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-contrib-7.4", reference:"7.4.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-doc-7.4", reference:"7.4.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-plperl-7.4", reference:"7.4.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-plpython-7.4", reference:"7.4.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-pltcl-7.4", reference:"7.4.17-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-server-dev-7.4", reference:"7.4.17-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
