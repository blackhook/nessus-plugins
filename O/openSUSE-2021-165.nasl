#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-165.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145423);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-2074", "CVE-2021-2129");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2021-165)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for virtualbox fixes the following issues :

Version update to 6.1.18 (released January 19 2021)

This is a maintenance release. The following items were fixed and/or
added :

  - Nested VM: Fixed hangs when executing SMP nested-guests
    under certain conditions on Intel hosts (bug #19315,
    #19561)

  - OCI integration: Cloud Instance parameters parsing is
    improved on import (bug #19156)

  - Network: UDP checksum offloading in e1000 no longer
    produces zero checksums (bug #19930)

  - Network: Fixed Host-Only Ethernet Adapter DHCP, guest os
    can not get IP on host resume (bug #19620)

  - NAT: Fixed mss parameter handing (bug #15256)

  - macOS host: Multiple optimizations for BigSur

  - Audio: Fixed issues with audio playback after host goes
    to sleep (bug #18594)

  - Documentation: Some content touch-up and table
    formatting fixes

  - Linux host and guest: Support kernel version 5.10 (bug
    #20055)

  - Solaris host: Fix regression breaking VGA text mode
    since version 6.1.0

  - Guest Additions: Fixed a build failure affecting CentOS
    8.2-2004 and later (bug #20091)

  - Guest Additions: Fixed a build failure affecting Linux
    kernels 3.2.0 through 3.2.50 (bug #20006)

  - Guest Additions: Fixed a VM segfault on copy with shared
    clipboard with X11 (bug #19226)

  - Shared Folder: Fixed error with remounting on Linux
    guests

  - Fixes CVE-2021-2074, boo#1181197 and CVE-2021-2129,
    boo#1181198.

  - Disable build of guest modules. These are included in
    recent kernels

  - Fix additional mouse control dialog issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181198");
  script_set_attribute(attribute:"solution", value:
"Update the affected virtualbox packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"python3-virtualbox-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-virtualbox-debuginfo-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-debuginfo-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-debugsource-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-devel-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-desktop-icons-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-tools-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-tools-debuginfo-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-x11-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-x11-debuginfo-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-host-source-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-debugsource-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-default-6.1.18_k5.3.18_lp152.60-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-default-debuginfo-6.1.18_k5.3.18_lp152.60-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-preempt-6.1.18_k5.3.18_lp152.60-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-preempt-debuginfo-6.1.18_k5.3.18_lp152.60-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-qt-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-qt-debuginfo-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-vnc-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-websrv-6.1.18-lp152.2.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-websrv-debuginfo-6.1.18-lp152.2.11.1") ) flag++;

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
