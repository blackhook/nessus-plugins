#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-943.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123383);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2019-943)");
  script_summary(english:"Check for the openSUSE-2019-943 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for virtualbox fixes the following issues :

virtualbox was updated to version 5.2.22 (released November 09 2018 by
Oracle).

Security issues fixed :

  - Fixed a guest-to-host excape via the e1000 virtual
    network driver (bsc#1115041).

Non-security issues fixed :

  - Audio: Fixed a regression in the Core Audio backend
    causing a hang when returning from host sleep when
    processing input buffers.

  - Audio: Fixed a potential crash in the HDA emulation if a
    stream has no valid mixer sink attached.

  - Linux Additions: Disable 3D for recent guests using
    Wayland (bug #18116).

  - Linux Additions: Fix for rebuilding kernel modules for
    new kernels on RPM guests.

  - Linux Additions: Further fixes for Linux 4.19.

  - Linux Additions: Fixed errors rebuilding initrd files
    with dracut on EL 6 (bug 18055#).

  - Linux Additions: Fixed 5.2.20 regression: guests not
    remembering the screen size after shutdown and restart
    (bug #18078)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115041"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected virtualbox packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.0", reference:"python3-virtualbox-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-virtualbox-debuginfo-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-debuginfo-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-debugsource-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-devel-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-desktop-icons-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-kmp-default-5.2.22_k4.12.14_lp150.12.48-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-kmp-default-debuginfo-5.2.22_k4.12.14_lp150.12.48-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-source-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-tools-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-tools-debuginfo-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-x11-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-x11-debuginfo-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-kmp-default-5.2.22_k4.12.14_lp150.12.48-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-kmp-default-debuginfo-5.2.22_k4.12.14_lp150.12.48-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-source-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-qt-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-qt-debuginfo-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-vnc-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-websrv-5.2.22-lp150.4.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-websrv-debuginfo-5.2.22-lp150.4.24.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3-virtualbox / python3-virtualbox-debuginfo / virtualbox / etc");
}
