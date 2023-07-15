#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1423.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119028);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-15686", "CVE-2018-15688");

  script_name(english:"openSUSE Security Update : systemd (openSUSE-2018-1423)");
  script_summary(english:"Check for the openSUSE-2018-1423 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd fixes the following issues :

Security issues fixed :

  - CVE-2018-15688: A buffer overflow vulnerability in the
    dhcp6 client of systemd allowed a malicious dhcp6 server
    to overwrite heap memory in systemd-networkd.
    (bsc#1113632)

  - CVE-2018-15686: A vulnerability in unit_deserialize of
    systemd allows an attacker to supply arbitrary state
    across systemd re-execution via NotifyAccess. This can
    be used to improperly influence systemd execution and
    possibly lead to root privilege escalation.
    (bsc#1113665)

Non-security issues fixed :

  - dhcp6: split assert_return() to be more debuggable when
    hit

  - core: skip unit deserialization and move to the next one
    when unit_deserialize() fails

  - core: properly handle deserialization of unknown unit
    types (#6476)

  - core: don't create Requires for workdir if 'missing ok'
    (bsc#1113083)

  - logind: use manager_get_user_by_pid() where appropriate

  - logind: rework manager_get_(user|session)_by_pid() a bit

  - login: fix user@.service case, so we don't allow nested
    sessions (#8051) (bsc#1112024)

  - core: be more defensive if we can't determine
    per-connection socket peer (#7329)

  - socket-util: introduce port argument in sockaddr_port()

  - service: fixup ExecStop for socket-activated shutdown
    (#4120)

  - service: Continue shutdown on socket activated unit on
    termination (#4108) (bsc#1106923)

  - cryptsetup: build fixes for 'add support for
    sector-size= option'

  - udev-rules: IMPORT cmdline does not recognize keys with
    similar names (bsc#1111278)

  - core: keep the kernel coredump defaults when
    systemd-coredump is disabled

  - core: shorten main() a bit, split out coredump
    initialization

  - core: set RLIMIT_CORE to unlimited by default
    (bsc#1108835)

  - core/mount: fstype may be NULL

  - journald: don't ship systemd-journald-audit.socket
    (bsc#1109252)

  - core: make 'tmpfs' dependencies on swapfs a 'default'
    dep, not an 'implicit' (bsc#1110445)

  - mount: make sure we unmount tmpfs mounts before we
    deactivate swaps (#7076)

  - tmp.mount.hm4: After swap.target (#3087)

  - Ship systemd-sysv-install helper via the main package
    This script was part of systemd-sysvinit sub-package but
    it was wrong since systemd-sysv-install is a script used
    to redirect enable/disable operations to chkconfig when
    the unit targets are sysv init scripts. Therefore it's
    never been a SySV init tool.

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113665"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-debuginfo-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-mini-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-mini-debuginfo-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-devel-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini-devel-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini1-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini1-debuginfo-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev1-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev1-debuginfo-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-myhostname-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-myhostname-debuginfo-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-mymachines-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-mymachines-debuginfo-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-bash-completion-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-debuginfo-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-debugsource-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-devel-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-logger-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-bash-completion-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-debuginfo-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-debugsource-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-devel-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-sysvinit-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-sysvinit-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-debuginfo-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-mini-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-mini-debuginfo-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsystemd0-32bit-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libudev1-32bit-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"nss-myhostname-32bit-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"nss-myhostname-debuginfo-32bit-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"systemd-32bit-228-62.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-62.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsystemd0-mini / libsystemd0-mini-debuginfo / libudev-mini-devel / etc");
}
