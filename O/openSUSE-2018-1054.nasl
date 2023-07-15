#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1054.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117796);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-7685");

  script_name(english:"openSUSE Security Update : libzypp / zypper (openSUSE-2018-1054)");
  script_summary(english:"Check for the openSUSE-2018-1054 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libzypp, zypper fixes the following issues :

Update libzypp to version 16.17.20 :

Security issues fixed :

  - PackageProvider: Validate delta rpms before caching
    (bsc#1091624, bsc#1088705, CVE-2018-7685)

  - PackageProvider: Validate downloaded rpm package
    signatures before caching (bsc#1091624, bsc#1088705,
    CVE-2018-7685)

Other bugs fixed :

  - lsof: use '-K i' if lsof supports it (bsc#1099847,
    bsc#1036304)

  - Handle http error 502 Bad Gateway in curl backend
    (bsc#1070851)

  - RepoManager: Explicitly request repo2solv to generate
    application pseudo packages.

  - libzypp-devel should not require cmake (bsc#1101349)

  - HardLocksFile: Prevent against empty commit without
    Target having been been loaded (bsc#1096803)

  - Avoid zombie tar processes (bsc#1076192)

Update to zypper to version 1.13.45 :

Other bugs fixed :

  - XML <install-summary> attribute `packages-to-change`
    added (bsc#1102429)

  - man: Strengthen that `--config FILE' affects
    zypper.conf, not zypp.conf (bsc#1100028)

  - Prevent nested calls to exit() if aborted by a signal
    (bsc#1092413)

  - ansi.h: Prevent ESC sequence strings from going out of
    scope (bsc#1092413)

  - Fix: zypper bash completion expands non-existing options
    (bsc#1049825)

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102429"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libzypp / zypper packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-aptitude");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-log");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/27");
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

if ( rpm_check(release:"SUSE42.3", reference:"libzypp-16.17.20-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzypp-debuginfo-16.17.20-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzypp-debugsource-16.17.20-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzypp-devel-16.17.20-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zypper-1.13.45-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zypper-aptitude-1.13.45-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zypper-debuginfo-1.13.45-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zypper-debugsource-1.13.45-20.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zypper-log-1.13.45-20.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzypp / libzypp-debuginfo / libzypp-debugsource / libzypp-devel / etc");
}
