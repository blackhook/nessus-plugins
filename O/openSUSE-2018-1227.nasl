#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1227.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118342);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-14680", "CVE-2018-14681", "CVE-2018-14682", "CVE-2018-15378");

  script_name(english:"openSUSE Security Update : clamav (openSUSE-2018-1227)");
  script_summary(english:"Check for the openSUSE-2018-1227 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for clamav fixes the following issues :

clamav was updated to version 0.100.2.

Following security issues were fixed :

  - CVE-2018-15378: Vulnerability in ClamAV's MEW unpacking
    feature that could allow an unauthenticated, remote
    attacker to cause a denial of service (DoS) condition on
    an affected device. (bsc#1110723)

  - CVE-2018-14680, CVE-2018-14681, CVE-2018-14682: more
    fixes for embedded libmspack. (bsc#1103040)

Following non-security issues were addressed :

  - Make freshclam more robust against lagging signature
    mirrors.

  - On-Access 'Extra Scanning', an opt-in minor feature of
    OnAccess scanning on Linux systems, has been disabled
    due to a known issue with resource cleanup
    OnAccessExtraScanning will be re-enabled in a future
    release when the issue is resolved. In the mean-time,
    users who enabled the feature in clamd.conf will see a
    warning informing them that the feature is not active.
    For details, see:
    https://bugzilla.clamav.net/show_bug.cgi?id=12048

  - Restore exit code compatibility of freshclam with
    versions before 0.100.0 when the virus database is
    already up to date (bsc#1104457)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.clamav.net/show_bug.cgi?id=12048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1103040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110723"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected clamav packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclamav7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclamav7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclammspack0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclammspack0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/24");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"clamav-0.100.2-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"clamav-debuginfo-0.100.2-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"clamav-debugsource-0.100.2-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"clamav-devel-0.100.2-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libclamav7-0.100.2-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libclamav7-debuginfo-0.100.2-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libclammspack0-0.100.2-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libclammspack0-debuginfo-0.100.2-lp150.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / clamav-debuginfo / clamav-debugsource / clamav-devel / etc");
}
