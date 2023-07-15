#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1330.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118562);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-0732", "CVE-2018-2909", "CVE-2018-3287", "CVE-2018-3288", "CVE-2018-3289", "CVE-2018-3290", "CVE-2018-3291", "CVE-2018-3292", "CVE-2018-3293", "CVE-2018-3294", "CVE-2018-3295", "CVE-2018-3296", "CVE-2018-3297", "CVE-2018-3298");

  script_name(english:"openSUSE Security Update : VirtualBox (openSUSE-2018-1330)");
  script_summary(english:"Check for the openSUSE-2018-1330 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for VirtualBox 5.2.20 fixes security issues and bugs.

A number of vulnerabilities were fixed a affecting multiple components
of VirtualBox bsc#1112097: CVE-2018-0732, CVE-2018-2909,
CVE-2018-3287, CVE-2018-3288, CVE-2018-3289, CVE-2018-3290,
CVE-2018-3291, CVE-2018-3292, CVE-2018-3293, CVE-2018-3294,
CVE-2018-3295, CVE-2018-3296, CVE-2018-3297, and CVE-2018-3298. 

This update also contains various bug fixes in the 5.2.20 release :

  - VMM: fixed task switches triggered by INTn instruction

  - Storage: fixed connecting to certain iSCSI targets

  - Storage: fixed handling of flush requests when
    configured to be ignored when the host I/O cache is used

  - Drag and drop fixes

  - Video recording: fixed starting video recording on VM
    power up

  - Various fixes to Linux Additions"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112097"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected VirtualBox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/31");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"python3-virtualbox-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-virtualbox-debuginfo-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-debuginfo-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-debugsource-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-devel-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-desktop-icons-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-kmp-default-5.2.20_k4.12.14_lp150.12.22-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-kmp-default-debuginfo-5.2.20_k4.12.14_lp150.12.22-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-source-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-tools-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-tools-debuginfo-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-x11-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-guest-x11-debuginfo-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-kmp-default-5.2.20_k4.12.14_lp150.12.22-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-kmp-default-debuginfo-5.2.20_k4.12.14_lp150.12.22-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-host-source-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-qt-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-qt-debuginfo-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-vnc-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-websrv-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"virtualbox-websrv-debuginfo-5.2.20-lp150.4.20.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-virtualbox-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-virtualbox-debuginfo-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-debuginfo-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-debugsource-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-devel-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-desktop-icons-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-kmp-default-5.2.20_k4.4.159_73-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-kmp-default-debuginfo-5.2.20_k4.4.159_73-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-source-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-tools-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-tools-debuginfo-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-x11-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-x11-debuginfo-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-host-kmp-default-5.2.20_k4.4.159_73-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-host-kmp-default-debuginfo-5.2.20_k4.4.159_73-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-host-source-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-qt-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-qt-debuginfo-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-vnc-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-websrv-5.2.20-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-websrv-debuginfo-5.2.20-60.1") ) flag++;

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
