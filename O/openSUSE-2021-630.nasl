#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-630.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149536);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2021-2074", "CVE-2021-2129", "CVE-2021-2264");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2021-630)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for virtualbox fixes the following issues :

  - Version bump to 6.1.20 (released April 20 2021 by
    Oracle) Fixes boo#1183329 'virtualbox 6.1.18 crashes
    when it runs nested VM' Fixes boo#1183125 'Leap 15.3
    installation in Virtualbox without VBox integration'
    Fixes CVE-2021-2264 and boo#1184542. The directory for
    the <user>.start files for autostarting VMs is moved
    from /etc/vbox to /etc/vbox/autostart.d. In addition,
    the autostart service is hardened (by Oracle).

  - change the modalias for guest-tools and guest-x11 to get
    them to autoinstall.

  - Own %(_sysconfdir)/X11/xinit/xinitrc.d as default
    packages (eg systemd) no longer do so, breaking package
    build.

  - Update fixes_for_leap15.3 for kernel API changes between
    5.3.18-45 and 5.3.18-47.

  - update-extpack.sh: explicitly use https:// protocol for
    authenticity. The http:// URL is currently redirected to
    https:// but don't rely on this.

  - Add code to generate guest modules for Leap 15.2 and
    Leap 15.3. The kernel versions do not allow window
    resizing. Files 'virtualbox-kmp-files-leap' and
    'vboxguestconfig.sh' are added

  - Fixes CVE-2021-2074, boo#1181197 and CVE-2021-2129,
    boo#1181198.

  - Under some circumstances, shared folders are mounted as
    root.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184542");
  script_set_attribute(attribute:"solution", value:
"Update the affected virtualbox packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2074");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2264");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");

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

if ( rpm_check(release:"SUSE15.2", reference:"python3-virtualbox-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-virtualbox-debuginfo-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-debuginfo-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-debugsource-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-devel-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-desktop-icons-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-source-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-tools-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-tools-debuginfo-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-x11-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-x11-debuginfo-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-host-source-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-debugsource-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-default-6.1.20_k5.3.18_lp152.72-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-default-debuginfo-6.1.20_k5.3.18_lp152.72-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-preempt-6.1.20_k5.3.18_lp152.72-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-preempt-debuginfo-6.1.20_k5.3.18_lp152.72-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-qt-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-qt-debuginfo-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-vnc-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-websrv-6.1.20-lp152.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-websrv-debuginfo-6.1.20-lp152.2.21.1") ) flag++;

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
