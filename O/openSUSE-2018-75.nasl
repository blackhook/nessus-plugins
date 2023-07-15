#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-75.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106289);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5715", "CVE-2018-2676", "CVE-2018-2685", "CVE-2018-2686", "CVE-2018-2687", "CVE-2018-2688", "CVE-2018-2689", "CVE-2018-2690", "CVE-2018-2693", "CVE-2018-2694", "CVE-2018-2698");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2018-75) (Spectre)");
  script_summary(english:"Check for the openSUSE-2018-75 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for virtualbox to version 5.1.32 fixes the following
issues :

The following vulnerabilities were fixed (boo#1076372) :

  - CVE-2017-5715: Systems with microprocessors utilizing
    speculative execution and indirect branch prediction may
    allow unauthorized disclosure of information to an
    attacker with local user access via a side-channel
    analysis, also known as 'Spectre', bsc#1068032.

  - CVE-2018-2676: Local authenticated attacker may gain
    elevated privileges

  - CVE-2018-2685: Local authenticated attacker may gain
    elevated privileges 

  - CVE-2018-2686: Local authenticated attacker may gain
    elevated privileges 

  - CVE-2018-2687: Local authenticated attacker may gain
    elevated privileges

  - CVE-2018-2688: Local authenticated attacker may gain
    elevated privileges

  - CVE-2018-2689: Local authenticated attacker may gain
    elevated privileges

  - CVE-2018-2690: Local authenticated attacker may gain
    elevated privileges

  - CVE-2018-2693: Local authenticated attacker may gain
    elevated privileges via guest additions

  - CVE-2018-2694: Local authenticated attacker may gain
    elevated privileges

  - CVE-2018-2698: Local authenticated attacker may gain
    elevated privileges 

The following bug fixes are included :

  - fix occasional screen corruption when host screen
    resolution is changed

  - increase proposed disk size when creating new VMs for
    Windows 7 and newer

  - fix broken communication with certain devices on Linux
    hosts

  - Fix problems using 256MB VRAM in raw-mode VMs

  - add HDA support for more exotic guests (e.g. Haiku)

  - fix playback with ALSA backend (5.1.28 regression)

  - fix a problem where OHCI emulation might sporadically
    drop data transfers"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076372"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/24");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"python-virtualbox-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-virtualbox-debuginfo-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-debuginfo-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-debugsource-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-devel-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-desktop-icons-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-kmp-default-5.1.32_k4.4.104_18.44-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-kmp-default-debuginfo-5.1.32_k4.4.104_18.44-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-source-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-tools-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-tools-debuginfo-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-x11-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-x11-debuginfo-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-kmp-default-5.1.32_k4.4.104_18.44-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-kmp-default-debuginfo-5.1.32_k4.4.104_18.44-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-source-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-qt-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-qt-debuginfo-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-vnc-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-websrv-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-websrv-debuginfo-5.1.32-19.49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-virtualbox-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-virtualbox-debuginfo-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-debuginfo-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-debugsource-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-devel-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-desktop-icons-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-kmp-default-5.1.32_k4.4.104_39-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-kmp-default-debuginfo-5.1.32_k4.4.104_39-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-source-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-tools-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-tools-debuginfo-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-x11-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-x11-debuginfo-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-host-kmp-default-5.1.32_k4.4.104_39-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-host-kmp-default-debuginfo-5.1.32_k4.4.104_39-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-host-source-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-qt-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-qt-debuginfo-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-vnc-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-websrv-5.1.32-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-websrv-debuginfo-5.1.32-42.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-virtualbox / python-virtualbox-debuginfo / virtualbox / etc");
}
