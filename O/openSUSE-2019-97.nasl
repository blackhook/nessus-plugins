#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-97.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121463);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-16864", "CVE-2018-16865", "CVE-2018-16866");

  script_name(english:"openSUSE Security Update : systemd (openSUSE-2019-97)");
  script_summary(english:"Check for the openSUSE-2019-97 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd provides the following fixes :

Security issues fixed :

  - CVE-2018-16864, CVE-2018-16865: Fixed two memory
    corruptions through attacker-controlled alloca()s
    (bsc#1120323)

  - CVE-2018-16866: Fixed an information leak in journald
    (bsc#1120323)

  - Fixed an issue during system startup in relation to
    encrypted swap disks (bsc#1119971)

Non-security issues fixed :

  - core: Queue loading transient units after setting their
    properties. (bsc#1115518)

  - logind: Stop managing VT switches if no sessions are
    registered on that VT. (bsc#1101591)

  - terminal-util: introduce vt_release() and vt_restore()
    helpers.

  - terminal: Unify code for resetting kbd utf8 mode a bit.

  - terminal Reset should honour default_utf8 kernel
    setting.

  - logind: Make session_restore_vt() static.

  - udev: Downgrade message when settting inotify watch up
    fails. (bsc#1005023)

  - log: Never log into foreign fd #2 in PID 1 or its
    pre-execve() children. (bsc#1114981)

  - udev: Ignore the exit code of systemd-detect-virt for
    memory hot-add. In SLE-12-SP3, 80-hotplug-cpu-mem.rules
    has a memory hot-add rule that uses systemd-detect-virt
    to detect non-zvm environment. The systemd-detect-virt
    returns exit failure code when it detected _none_ state.
    The exit failure code causes that the hot-add memory
    block can not be set to online. (bsc#1076696)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120323"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/30");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-debuginfo-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-mini-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-mini-debuginfo-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-devel-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini-devel-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini1-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini1-debuginfo-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev1-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev1-debuginfo-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-myhostname-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-myhostname-debuginfo-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-mymachines-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-mymachines-debuginfo-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-bash-completion-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-debuginfo-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-debugsource-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-devel-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-logger-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-bash-completion-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-debuginfo-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-debugsource-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-devel-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-sysvinit-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-sysvinit-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-debuginfo-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-mini-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-mini-debuginfo-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsystemd0-32bit-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libudev1-32bit-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"nss-myhostname-32bit-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"nss-myhostname-debuginfo-32bit-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"systemd-32bit-228-65.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-65.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsystemd0-mini / libsystemd0-mini-debuginfo / libudev-mini-devel / etc");
}
