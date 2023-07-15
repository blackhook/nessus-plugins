#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-389.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109294);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-3737", "CVE-2017-9798", "CVE-2018-0739", "CVE-2018-2830", "CVE-2018-2831", "CVE-2018-2835", "CVE-2018-2836", "CVE-2018-2837", "CVE-2018-2842", "CVE-2018-2843", "CVE-2018-2844", "CVE-2018-2845", "CVE-2018-2860");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2018-389) (Optionsbleed)");
  script_summary(english:"Check for the openSUSE-2018-389 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for VirtualBox to version 5.1.36 fixes multiple issues :

Security issues fixed :

  - CVE-2018-0739: Unauthorized remote attacker may have
    caused a hang or frequently repeatable crash (complete
    DOS)

  - CVE-2018-2830: Attacker with host login may have
    compromised Virtualbox or further system services after
    interaction with a third user

  - CVE-2018-2831: Attacker with host login may have
    compromised VirtualBox or further system services,
    allowing read access to some data

  - CVE-2018-2835: Attacker with host login may have gained
    control over VirtualBox and possibly further system
    services after interacting with a third user

  - CVE-2018-2836: Attacker with host login may have gained
    control over VirtualBox and possibly further system
    services after interacting with a third user

  - CVE-2018-2837: Attacker with host login may have gained
    control over VirtualBox and possibly further system
    services after interacting with a third user

  - CVE-2018-2842: Attacker with host login may have gained
    control over VirtualBox and possibly further system
    services after interacting with a third user

  - CVE-2018-2843: Attacker with host login may have gained
    control over VirtualBox and possibly further system
    services after interacting with a third user 

  - CVE-2018-2844: Attacker with host login may have gained
    control over VirtualBox and possibly further system
    services after interacting with a third user 

  - CVE-2018-2845: Attacker with host login may have caused
    a hang or frequently repeatable crash (complete DOS),
    and perform unauthorized read and write operation to
    some VirtualBox accessible data

  - CVE-2018-2860: Privileged attacker may have gained
    control over VirtualBox and possibly further system
    services

http://www.oracle.com/technetwork/security-advisory/cpuapr2018verbose-
3678108.html
http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067
.html#AppendixOVIR

This update also contains all upstream fixes and improvements in the
stable 5.1.36 release."
  );
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html#AppendixOVIR
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05e0bcf5"
  );
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2018verbose-3678108.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7eca6abf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089997"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/23");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/24");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"python-virtualbox-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-virtualbox-debuginfo-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-debuginfo-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-debugsource-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-devel-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-desktop-icons-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-kmp-default-5.1.36_k4.4.126_48-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-kmp-default-debuginfo-5.1.36_k4.4.126_48-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-source-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-tools-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-tools-debuginfo-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-x11-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-x11-debuginfo-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-host-kmp-default-5.1.36_k4.4.126_48-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-host-kmp-default-debuginfo-5.1.36_k4.4.126_48-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-host-source-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-qt-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-qt-debuginfo-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-vnc-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-websrv-5.1.36-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-websrv-debuginfo-5.1.36-50.1") ) flag++;

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
