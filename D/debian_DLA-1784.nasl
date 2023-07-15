#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1784-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124874);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-1784-1 : postgresql-9.4 new minor release");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The PostgreSQL project has release a new minor release of the 9.4
branch.

For Debian 8 'Jessie', this has been uploaded as version
9.4.22-0+deb8u1.

We recommend that you upgrade your postgresql-9.4 packages.

Note that the end of life of the 9.4 branch is scheduled for February
2020. Please consider upgrading to a newer major release before that
point.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/05/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/postgresql-9.4"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg-compat3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpgtypes3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpq-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-client-9.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-contrib-9.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-doc-9.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plperl-9.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plpython-9.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plpython3-9.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-pltcl-9.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-server-dev-9.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libecpg-compat3", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libecpg-dev", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libecpg6", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpgtypes3", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpq-dev", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpq5", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-9.4", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-9.4-dbg", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-client-9.4", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-contrib-9.4", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-doc-9.4", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-plperl-9.4", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-plpython-9.4", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-plpython3-9.4", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-pltcl-9.4", reference:"9.4.22-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-server-dev-9.4", reference:"9.4.22-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
