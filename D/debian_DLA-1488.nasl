#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1488-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112227);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-3058", "CVE-2018-3063", "CVE-2018-3064", "CVE-2018-3066");

  script_name(english:"Debian DLA-1488-1 : mariadb-10.0 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been discovered in the MariaDB database server.
The vulnerabilities are addressed by upgrading MariaDB to the new
upstream version 10.0.36. Please see the MariaDB 10.0 Release Notes
for further details :

https://mariadb.com/kb/en/mariadb/mariadb-10036-release-notes/

CVE-2018-3058

Easily exploitable vulnerability allows low privileged attacker with
network access via multiple protocols to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
update, insert or delete access to some of MySQL Server accessible
data.

CVE-2018-3063

Easily exploitable vulnerability allows high privileged attacker with
network access via multiple protocols to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS)
of MySQL Server.

CVE-2018-3064

Easily exploitable vulnerability allows low privileged attacker with
network access via multiple protocols to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a hang or frequently repeatable crash (complete DOS)
of MySQL Server as well as unauthorized update, insert or delete
access to some of MySQL Server accessible data.

CVE-2018-3066

Difficult to exploit vulnerability allows high privileged attacker
with network access via multiple protocols to compromise MySQL Server.
Successful attacks of this vulnerability can result in unauthorized
update, insert or delete access to some of MySQL Server accessible
data as well as unauthorized read access to a subset of MySQL Server
accessible data.

For Debian 8 'Jessie', these problems have been fixed in version
10.0.36-0+deb8u1.

We recommend that you upgrade your mariadb-10.0 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/08/msg00036.html"
  );
  # https://mariadb.com/kb/en/mariadb/mariadb-10036-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/library/mariadb-10036-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/mariadb-10.0"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmariadbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-client-10.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-client-core-10.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-connect-engine-10.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-oqgraph-engine-10.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-server-10.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-server-core-10.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mariadb-test-10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/04");
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
if (deb_check(release:"8.0", prefix:"libmariadbd-dev", reference:"10.0.36-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-client", reference:"10.0.36-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-client-10.0", reference:"10.0.36-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-client-core-10.0", reference:"10.0.36-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-common", reference:"10.0.36-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-connect-engine-10.0", reference:"10.0.36-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-oqgraph-engine-10.0", reference:"10.0.36-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-server", reference:"10.0.36-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-server-10.0", reference:"10.0.36-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-server-core-10.0", reference:"10.0.36-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-test", reference:"10.0.36-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"mariadb-test-10.0", reference:"10.0.36-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
