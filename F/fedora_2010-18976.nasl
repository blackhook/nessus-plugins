#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-18976.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51412);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2009-5016", "CVE-2010-3709", "CVE-2010-3710", "CVE-2010-3870", "CVE-2010-4150", "CVE-2010-4156", "CVE-2010-4409");
  script_bugtraq_id(43926, 44605, 44718, 44727, 44889, 44980, 45119);
  script_xref(name:"FEDORA", value:"2010-18976");

  script_name(english:"Fedora 14 : maniadrive-1.2-23.fc14 / php-5.3.4-1.fc14.1 / php-eaccelerator-0.9.6.1-3.fc14 (2010-18976)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Enhancements and Fixes in PHP 5.3.4 :

  - Fixed crash in zip extract method (possible CWE-170).

    - Paths with NULL in them (foo\0bar.txt) are now
      considered as invalid (CVE-2006-7243).

    - Fixed a possible double free in imap extension
      (Identified by Mateusz Kocielski). (CVE-2010-4150).

    - Fixed NULL pointer dereference in
      ZipArchive::getArchiveComment. (CVE-2010-3709).

    - Fixed possible flaw in open_basedir (CVE-2010-3436).

    - Fixed MOPS-2010-24, fix string validation.
      (CVE-2010-2950).

    - Fixed symbolic resolution support when the target is a
      DFS share.

    - Fixed bug #52929 (Segfault in filter_var with
      FILTER_VALIDATE_EMAIL with large amount of data)
      (CVE-2010-3710).

Key Bug Fixes in PHP 5.3.4 include :

  - Added stat support for zip stream.

    - Added follow_location (enabled by default) option for
      the http stream support.

    - Added a 3rd parameter to get_html_translation_table.
      It now takes a charset hint, like htmlentities et al.

    - Implemented FR #52348, added new constant
      ZEND_MULTIBYTE to detect zend multibyte at runtime.

Full upstream Changelog : http://www.php.net/ChangeLog-5.php#5.3.4

This update also provides php-eaccelerator and maniadrive packages
rebuild against update php.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.3.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=646684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=649056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=651206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=651682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=652836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=656917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=660382"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-January/052843.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?730c2771"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-January/052844.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a183384"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-January/052845.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85fdc87e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected maniadrive, php and / or php-eaccelerator
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:maniadrive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-eaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"maniadrive-1.2-23.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"php-5.3.4-1.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"php-eaccelerator-0.9.6.1-3.fc14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "maniadrive / php / php-eaccelerator");
}
