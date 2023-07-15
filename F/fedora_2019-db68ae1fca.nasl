#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-db68ae1fca.
#

include("compat.inc");

if (description)
{
  script_id(131461);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/09");

  script_cve_id("CVE-2019-18622");
  script_xref(name:"FEDORA", value:"2019-db68ae1fca");

  script_name(english:"Fedora 31 : phpMyAdmin (2019-db68ae1fca)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upstream announcement :

**phpMyAdmin 4.9.2 is released**

2019-11-22

Welcome to phpMyAdmin 4.9.2, a bugfix release that also contains a
security fix.

This security fix is part of an ongoing effort to improve the security
of the Designer feature and is designated **PMASA-2019-5**. There is
also an improvement for how we sanitize Git version information shown
on the home page, thanks to Ali Hubail.

This release includes fixes for many bugs, including :

  - Fixes for the 'Failed to set session cookie' error which
    relates to the cookie name. In some cases, data stored
    in the cookie (such as the previously-used user account)
    may not be loaded from a previous phpMyAdmin cookie the
    first time you run version 4.9.2

  - Fix for Advisor with MySQL 8.0.3 and newer

  - Fix PHP deprecation errors

  - Fix a situation where exporting users after a delete
    query could remove users

  - Fix incorrect 'You do not have privileges to manipulate
    with the users!' warning

  - Fix copying a database's privileges and several other
    problems moving columns with MariaDB

  - Fix for phpMyAdmin not selecting all the values when
    using shift-click to select during Export

There are many, many more bug fixes thanks to the efforts of our
developers and other contributors.

The phpMyAdmin team

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-db68ae1fca"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"phpMyAdmin-4.9.2-1.fc31")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
