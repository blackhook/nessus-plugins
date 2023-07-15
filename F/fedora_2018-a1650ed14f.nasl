#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-a1650ed14f.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107010);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-7260");
  script_xref(name:"FEDORA", value:"2018-a1650ed14f");

  script_name(english:"Fedora 27 : php-phpmyadmin-motranslator / php-phpmyadmin-sql-parser / etc (2018-a1650ed14f)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From upstream announcement :

**Security fix: phpMyAdmin 4.7.8 is released**

Welcome to phpMyAdmin 4.7.8, a security releaes also containing
regular maintenance bug fixes.

The security fix relates to a self-XSS vulnerability in the central
columns feature that is reported as PMASA-2018-1
https://www.phpmyadmin.net/security/PMASA-2018-1/. Thanks to Mayur
Udiniya https://www.linkedin.com/in/mayur-udiniya-09247b129/ for
finding and responsibly disclosing this flaw.

We recommend all users upgrade to resolve this security problem.

A complete list of new features and bugs that have been fixed is
available in the ChangeLog file or changelog.php included with this
release.

Notable changes since 4.7.7 :

  - Fixed error handling with PHP 7.2

  - Fixed resetting default setting values

  - Fixed fallback value for collation connection

Additionally, there have been continuous improvements to many of the
translations. If you don't see your language or find a problem, you
can contribute too; see https://www.phpmyadmin.net/translate/ for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-a1650ed14f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.linkedin.com/in/mayur-udiniya-09247b129/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2018-1/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/translate/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected php-phpmyadmin-motranslator,
php-phpmyadmin-sql-parser and / or phpMyAdmin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-phpmyadmin-motranslator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-phpmyadmin-sql-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^27([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 27", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC27", reference:"php-phpmyadmin-motranslator-4.0-1.fc27")) flag++;
if (rpm_check(release:"FC27", reference:"php-phpmyadmin-sql-parser-4.2.4-3.fc27")) flag++;
if (rpm_check(release:"FC27", reference:"phpMyAdmin-4.7.8-1.fc27")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-phpmyadmin-motranslator / php-phpmyadmin-sql-parser / etc");
}
