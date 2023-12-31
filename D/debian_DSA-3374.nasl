#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3374. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86447);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-5288", "CVE-2015-5289");
  script_xref(name:"DSA", value:"3374");

  script_name(english:"Debian DSA-3374-1 : postgresql-9.4 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in PostgreSQL-9.4, a SQL
database system.

  - CVE-2015-5288
    Josh Kupershmidt discovered a vulnerability in the
    crypt() function in the pgCrypto extension. Certain
    invalid salt arguments can cause the server to crash or
    to disclose a few bytes of server memory.

  - CVE-2015-5289
    Oskari Saarenmaa discovered that json or jsonb input
    values constructed from arbitrary user input can crash
    the PostgreSQL server and cause a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/postgresql-9.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3374"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql-9.4 packages.

For the stable distribution (jessie), these problems have been fixed
in version 9.4.5-0+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/20");
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
if (deb_check(release:"8.0", prefix:"libecpg-compat3", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libecpg-dev", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libecpg6", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpgtypes3", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpq-dev", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpq5", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-9.4", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-9.4-dbg", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-client-9.4", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-contrib-9.4", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-doc-9.4", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-plperl-9.4", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-plpython-9.4", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-plpython3-9.4", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-pltcl-9.4", reference:"9.4.5-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-server-dev-9.4", reference:"9.4.5-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
