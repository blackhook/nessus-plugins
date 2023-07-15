#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-925.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138722);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-2741", "CVE-2020-2742", "CVE-2020-2743", "CVE-2020-2748", "CVE-2020-2758", "CVE-2020-2894", "CVE-2020-2902", "CVE-2020-2905", "CVE-2020-2907", "CVE-2020-2908", "CVE-2020-2909", "CVE-2020-2910", "CVE-2020-2911", "CVE-2020-2913", "CVE-2020-2914", "CVE-2020-2929", "CVE-2020-2951", "CVE-2020-2958", "CVE-2020-2959");

  script_name(english:"openSUSE Security Update : Virtualbox (openSUSE-2020-925)");
  script_summary(english:"Check for the openSUSE-2020-925 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Virtualbox was updated to 6.0.22 (released May 15 2020 by Oracle)

This is a maintenance release. The following items were fixed and/or
added :

Guest Additions: Build problems fix with Oracle Linux 8.2 (Red Hat
compatible kernel) / Red Hat Enterprise Linux 8.2 / CentOS 8.2 (bug
#19391) Guest Control/VBoxManage: fix handling of multiple environment
variables supplied to 'VBoxManage guestcontrol VM run' (6.1.6/6.0.20
regression; bug #19518)

Version bump to 6.0.20 (released April 14 2020 by Oracle)

This is a maintenance release. The following items were fixed and/or
added :

  - USB: Multiple enhancements improving prformance and
    stability

  - VBoxManage: Multiple fixes for guestcontrol command

  - Graphics: Enhancements in 2D and 3D acceleration and
    rendering

  - API: Fix for exception handling bug in Python bindings

  - Linux host and guest: Support Linux kernel 5.6 (bug
    #19312)

This update fixes the following security issues: CVE-2020-2741,
CVE-2020-2742, CVE-2020-2743, CVE-2020-2748, CVE-2020-2758,
CVE-2020-2894, CVE-2020-2902, CVE-2020-2905, CVE-2020-2907,
CVE-2020-2908, CVE-2020-2909, CVE-2020-2910, CVE-2020-2911,
CVE-2020-2913, CVE-2020-2914, CVE-2020-2929, CVE-2020-2951,
CVE-2020-2958, CVE-2020-2959 (bsc#1169628)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169628"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected Virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2929");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"python3-virtualbox-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-virtualbox-debuginfo-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-debuginfo-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-debugsource-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-devel-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-desktop-icons-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-source-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-tools-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-tools-debuginfo-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-x11-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-guest-x11-debuginfo-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-host-source-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-kmp-default-6.0.22_k4.12.14_lp151.28.52-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-kmp-default-debuginfo-6.0.22_k4.12.14_lp151.28.52-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-qt-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-qt-debuginfo-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-vnc-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-websrv-6.0.22-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"virtualbox-websrv-debuginfo-6.0.22-lp151.2.15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3-virtualbox / python3-virtualbox-debuginfo / virtualbox / etc");
}
