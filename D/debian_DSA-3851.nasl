#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3851. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100165);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-7484", "CVE-2017-7485", "CVE-2017-7486");
  script_xref(name:"DSA", value:"3851");

  script_name(english:"Debian DSA-3851-1 : postgresql-9.4 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in the PostgreSQL database
system :

  - CVE-2017-7484
    Robert Haas discovered that some selectivity estimators
    did not validate user privileges which could result in
    information disclosure.

  - CVE-2017-7485
    Daniel Gustafsson discovered that the PGREQUIRESSL
    environment variable did no longer enforce a TLS
    connection.

  - CVE-2017-7486
    Andrew Wheelwright discovered that user mappings were
    insufficiently restricted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-7486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/postgresql-9.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3851"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql-9.4 packages.

For the stable distribution (jessie), these problems have been fixed
in version 9.4.12-0+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/15");
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
if (deb_check(release:"8.0", prefix:"libecpg-compat3", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libecpg-dev", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libecpg6", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpgtypes3", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpq-dev", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpq5", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-9.4", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-9.4-dbg", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-client-9.4", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-contrib-9.4", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-doc-9.4", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-plperl-9.4", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-plpython-9.4", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-plpython3-9.4", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-pltcl-9.4", reference:"9.4.12-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-server-dev-9.4", reference:"9.4.12-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
