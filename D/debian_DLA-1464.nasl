#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1464-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111762);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-10915");

  script_name(english:"Debian DLA-1464-1 : postgresql-9.4 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An unprivileged user of dblink or postgres_fdw could bypass the checks
intended to prevent use of server-side credentials, such as a
~/.pgpass file owned by the operating-system user running the server.
Servers allowing peer authentication on local connections are
particularly vulnerable. Other attacks such as SQL injection into a
postgres_fdw session are also possible. Attacking postgres_fdw in this
way requires the ability to create a foreign server object with
selected connection parameters, but any user with access to dblink
could exploit the problem. In general, an attacker with the ability to
select the connection parameters for a libpq-using application could
cause mischief, though other plausible attack scenarios are harder to
think of. Our thanks to Andrew Krasichkov for reporting this issue.

For Debian 8 'Jessie', this problem has been fixed in version
9.4.19-0+deb8u1.

We recommend that you upgrade your postgresql-9.4 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/08/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/postgresql-9.4"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libecpg-compat3", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libecpg-dev", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libecpg6", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpgtypes3", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpq-dev", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpq5", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-9.4", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-9.4-dbg", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-client-9.4", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-contrib-9.4", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-doc-9.4", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-plperl-9.4", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-plpython-9.4", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-plpython3-9.4", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-pltcl-9.4", reference:"9.4.19-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"postgresql-server-dev-9.4", reference:"9.4.19-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
