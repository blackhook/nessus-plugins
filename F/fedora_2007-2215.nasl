#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-2215.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27759);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2007-1887", "CVE-2007-1900", "CVE-2007-2756", "CVE-2007-2872", "CVE-2007-3007");
  script_bugtraq_id(24259, 24261, 25498);
  script_xref(name:"FEDORA", value:"2007-2215");

  script_name(english:"Fedora 7 : php-5.2.4-1.fc7 (2007-2215)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest release of PHP 5.2.

A number of security issues have been fixed.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=246533"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-September/003846.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c3e030b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-September/003922.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5af3d17b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-mhash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"php-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-bcmath-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-cli-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-common-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-dba-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-debuginfo-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-devel-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-gd-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-imap-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-ldap-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-mbstring-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-mcrypt-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-mhash-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-mssql-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-mysql-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-ncurses-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-odbc-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-pdo-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-pgsql-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-snmp-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-soap-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-tidy-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-xml-5.2.4-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"php-xmlrpc-5.2.4-1.fc7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
}
