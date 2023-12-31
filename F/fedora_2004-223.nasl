#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-223.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(13749);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2004-223");

  script_name(english:"Fedora Core 2 : php-4.3.8-2.1 (2004-223)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest release of PHP 4, including fixes for
security issues in memory limit handling (CVE-2004-0594), and the
strip_tags function (CVE-2004-0595). CVE-2004-0595 is not known to be
exploitable in the default configuration if using httpd 2.0.50, but
can be triggered if the 'register_globals' setting has been enabled.
CVE-2004-0595 can allow a possible cross-site-scripting attack with
some browsers.

The mbstring extension has been moved into the php-mbstring subpackage
in this update to reduce the overall package size.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-July/000229.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfe80132"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-domxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 2.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC2", reference:"php-4.3.8-2.1")) flag++;
if (rpm_check(release:"FC2", reference:"php-debuginfo-4.3.8-2.1")) flag++;
if (rpm_check(release:"FC2", reference:"php-devel-4.3.8-2.1")) flag++;
if (rpm_check(release:"FC2", reference:"php-domxml-4.3.8-2.1")) flag++;
if (rpm_check(release:"FC2", reference:"php-imap-4.3.8-2.1")) flag++;
if (rpm_check(release:"FC2", reference:"php-ldap-4.3.8-2.1")) flag++;
if (rpm_check(release:"FC2", reference:"php-mbstring-4.3.8-2.1")) flag++;
if (rpm_check(release:"FC2", reference:"php-mysql-4.3.8-2.1")) flag++;
if (rpm_check(release:"FC2", reference:"php-odbc-4.3.8-2.1")) flag++;
if (rpm_check(release:"FC2", reference:"php-pear-4.3.8-2.1")) flag++;
if (rpm_check(release:"FC2", reference:"php-pgsql-4.3.8-2.1")) flag++;
if (rpm_check(release:"FC2", reference:"php-snmp-4.3.8-2.1")) flag++;
if (rpm_check(release:"FC2", reference:"php-xmlrpc-4.3.8-2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-debuginfo / php-devel / php-domxml / php-imap / php-ldap / etc");
}
