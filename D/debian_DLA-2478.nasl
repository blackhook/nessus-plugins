#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2478-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(143461);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-25694", "CVE-2020-25695", "CVE-2020-25696");
  script_xref(name:"IAVB", value:"2020-B-0069-S");

  script_name(english:"Debian DLA-2478-1 : postgresql-9.6 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been found in the PostgreSQL database
system.

CVE-2020-25694

Peter Eisentraut found that database reconnections may drop options
from the original connection, such as encryption, which could lead to
information disclosure or a man-in-the-middle attack.

CVE-2020-25695

Etienne Stalmans reported that a user with permissions to create
non-temporary objects in an schema can execute arbitrary SQL functions
as a superuser.

CVE-2020-25696

Nick Cleaton found that the \gset command modified variables that
control the psql behaviour, which could result in a compromised or
malicious server executing arbitrary code in the user session.

For Debian 9 stretch, these problems have been fixed in version
9.6.20-0+deb9u1.

We recommend that you upgrade your postgresql-9.6 packages.

For the detailed security status of postgresql-9.6 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/postgresql-9.6

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/postgresql-9.6"
  );
  # https://security-tracker.debian.org/tracker/source-package/postgresql-9.6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?350b32e8"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25696");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg-compat3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpgtypes3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpq-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-client-9.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-contrib-9.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-doc-9.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plperl-9.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plpython-9.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-plpython3-9.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-pltcl-9.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-server-dev-9.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libecpg-compat3", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libecpg-dev", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libecpg6", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpgtypes3", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpq-dev", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpq5", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-9.6", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-9.6-dbg", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-client-9.6", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-contrib-9.6", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-doc-9.6", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-plperl-9.6", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-plpython-9.6", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-plpython3-9.6", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-pltcl-9.6", reference:"9.6.20-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"postgresql-server-dev-9.6", reference:"9.6.20-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
