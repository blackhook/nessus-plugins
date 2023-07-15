#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-383.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109238);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-1000166");

  script_name(english:"openSUSE Security Update : cfitsio (openSUSE-2018-383)");
  script_summary(english:"Check for the openSUSE-2018-383 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cfitsio fixes the following issues :

Security issues fixed :

  - CVE-2018-1000166: Unsafe use of sprintf() can allow a
    remote unauthenticated attacker to execute arbitrary
    code (boo#1088590)

This update to version 3.430 also contains a number of upstream bug
fixes.

The following tracked packaging changes are included :

  - boo#1082318: package licence text as license, not as
    documentation"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088590"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cfitsio packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cfitsio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cfitsio-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cfitsio-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cfitsio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcfitsio5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcfitsio5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"cfitsio-3.430-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cfitsio-debuginfo-3.430-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cfitsio-debugsource-3.430-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cfitsio-devel-3.430-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcfitsio5-3.430-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcfitsio5-debuginfo-3.430-4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cfitsio / cfitsio-debuginfo / cfitsio-debugsource / cfitsio-devel / etc");
}
