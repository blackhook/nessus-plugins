#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-178.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96900);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-5545", "CVE-2017-3290", "CVE-2017-3316", "CVE-2017-3332");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2017-178)");
  script_summary(english:"Check for the openSUSE-2017-178 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for virtualbox to version 5.0.32 fixes the following
issues :

These security issues were fixed :

  - CVE-2016-5545: Vulnerability in the GUI subcomponent of
    virtualbox allows unauthenticated attacker unauthorized
    update, insert or delete access to some data as well as
    unauthorized read access to a subset of VirtualBox
    accessible data and unauthorized ability to cause a
    partial denial of service (bsc#1020856).

  - CVE-2017-3290: Vulnerability in the Shared Folder
    subcomponent of virtualbox allows high privileged
    attacker unauthorized creation, deletion or modification
    access to critical data and unauthorized ability to
    cause a hang or frequently repeatable crash
    (bsc#1020856).

  - CVE-2017-3316: Vulnerability in the GUI subcomponent of
    virtualbox allows high privileged attacker with network
    access via multiple protocols to compromise Oracle VM
    VirtualBox (bsc#1020856).

  - CVE-2017-3332: Vulnerability in the SVGA Emulation
    subcomponent of virtualbox allows low privileged
    attacker unauthorized creation, deletion or modification
    access to critical data and unauthorized ability to
    cause a hang or frequently repeatable crash
    (bsc#1020856).

For other changes please read the changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020856"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"python-virtualbox-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-virtualbox-debuginfo-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-debuginfo-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-debugsource-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-devel-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-guest-desktop-icons-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-guest-kmp-default-5.0.32_k4.1.36_44-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-guest-kmp-default-debuginfo-5.0.32_k4.1.36_44-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-guest-tools-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-guest-tools-debuginfo-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-guest-x11-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-guest-x11-debuginfo-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-host-kmp-default-5.0.32_k4.1.36_44-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-host-kmp-default-debuginfo-5.0.32_k4.1.36_44-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-host-source-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-qt-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-qt-debuginfo-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-websrv-5.0.32-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"virtualbox-websrv-debuginfo-5.0.32-34.1") ) flag++;

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
