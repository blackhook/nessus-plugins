#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-216.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107050);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-18078");

  script_name(english:"openSUSE Security Update : systemd (openSUSE-2018-216)");
  script_summary(english:"Check for the openSUSE-2018-216 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd fixes the following issues :

Security issue fixed :

  - CVE-2017-18078: tmpfiles: refuse to chown()/chmod()
    files which are hardlinked, unless protected_hardlinks
    sysctl is on. This could be used by local attackers to
    gain privileges (bsc#1077925)

Non Security issues fixed :

  - core: use id unit when retrieving unit file state
    (#8038) (bsc#1075801)

  - cryptsetup-generator: run cryptsetup service before swap
    unit (#5480)

  - udev-rules: all values can contain escaped double quotes
    now (#6890)

  - strv: fix buffer size calculation in strv_join_quoted()

  - tmpfiles: change ownership of symlinks too

  - stdio-bridge: Correctly propagate error

  - stdio-bridge: remove dead code

  - remove bus-proxyd (bsc#1057974)

  - core/timer: Prevent timer looping when unit cannot start
    (bsc#1068588)

  - Make systemd-timesyncd use the openSUSE NTP servers by
    default Previously systemd-timesyncd used the Google
    Public NTP servers time(1..4).google.com

  - Don't ship /usr/lib/systemd/system/tmp.mnt at all
    (bsc#1071224) But we still ship a copy in /var. Users
    who want to use tmpfs on /tmp are supposed to add a
    symlink in /etc/ pointing to the copy shipped in /var.
    To support the update path we automatically create the
    symlink if tmp.mount in use is located in /usr.

  - Enable systemd-networkd on Leap distros only
    (bsc#1071311)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077925"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");
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

if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-debuginfo-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-mini-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-mini-debuginfo-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-devel-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini-devel-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini1-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini1-debuginfo-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev1-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev1-debuginfo-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-myhostname-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-myhostname-debuginfo-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-mymachines-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-mymachines-debuginfo-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-bash-completion-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-debuginfo-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-debugsource-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-devel-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-logger-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-bash-completion-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-debuginfo-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-debugsource-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-devel-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-sysvinit-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-sysvinit-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-debuginfo-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-mini-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-mini-debuginfo-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsystemd0-32bit-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libudev1-32bit-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"nss-myhostname-32bit-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"nss-myhostname-debuginfo-32bit-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"systemd-32bit-228-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-44.1") ) flag++;

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
