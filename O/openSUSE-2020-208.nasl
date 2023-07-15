#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-208.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(133666);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/14");

  script_cve_id("CVE-2019-20386", "CVE-2020-1712");

  script_name(english:"openSUSE Security Update : systemd (openSUSE-2020-208)");
  script_summary(english:"Check for the openSUSE-2020-208 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd fixes the following issues :

  - CVE-2020-1712 (bsc#bsc#1162108) Fix a heap
    use-after-free vulnerability, when asynchronous Polkit
    queries were performed while handling Dbus messages. A
    local unprivileged attacker could have abused this flaw
    to crash systemd services or potentially execute code
    and elevate their privileges, by sending specially
    crafted Dbus messages.

  - Use suse.pool.ntp.org server pool on SLE distros
    (jsc#SLE-7683)

  - libblkid: open device in nonblock mode. (bsc#1084671)

  - udev/cdrom_id: Do not open CD-rom in exclusive mode.
    (bsc#1154256)

  - bus_open leak sd_event_source when udevadm
    trigger&#x3002; (bsc#1161436 CVE-2019-20386)

  - fileio: introduce read_full_virtual_file() for reading
    virtual files in sysfs, procfs (bsc#1133495 bsc#1159814)

  - fileio: initialize errno to zero before we do fread()

  - fileio: try to read one byte too much in
    read_full_stream()

  - logind: consider 'greeter' sessions suitable as
    'display' sessions of a user (bsc#1158485)

  - logind: never elect a session that is stopping as
    display

  - journal: include kmsg lines from the systemd process
    which exec()d us (#8078)

  - udevd: don't use monitor after manager_exit()

  - udevd: capitalize log messages in on_sigchld()

  - udevd: merge conditions to decrease indentation

  - Revert 'udevd: fix crash when workers time out after
    exit is signal caught'

  - core: fragments of masked units ought not be considered
    for NeedDaemonReload (#7060) (bsc#1156482)

  - udevd: fix crash when workers time out after exit is
    signal caught

  - udevd: wait for workers to finish when exiting
    (bsc#1106383)

  - Improve bash completion support (bsc#1155207)

  - shell-completion: systemctl: do not list template units
    in (re,)start

  - shell-completion: systemctl: pass current word to all
    list_unit*

  - bash-completion: systemctl: pass current partial unit to
    list-unit* (bsc#1155207)

  - bash-completion: systemctl: use systemctl --no-pager

  - bash-completion: also suggest template unit files

  - bash-completion: systemctl: add missing options and
    verbs

  - bash-completion: use the first argument instead of the
    global variable (#6457)

  - networkd: VXLan Make group and remote variable separate
    (bsc#1156213)

  - networkd: vxlan require Remote= to be a non multicast
    address (#8117) (bsc#1156213)

  - fs-util: let's avoid unnecessary strerror()

  - fs-util: introduce inotify_add_watch_and_warn() helper

  - ask-password: improve log message when inotify limit is
    reached (bsc#1155574)

  - shared/install: failing with -ELOOP can be due to the
    use of an alias in install_error() (bsc#1151377)

  - man: alias names can't be used with enable command
    (bsc#1151377)

  - Add boot option to not use swap at system start
    (jsc#SLE-7689)

  - Allow YaST to select Iranian (Persian, Farsi) keyboard
    layout (bsc#1092920) This update was imported from the
    SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162108"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1712");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsystemd0-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-myhostname-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-mymachines-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nss-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-container-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-coredump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-container-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-container-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-coredump-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-coredump-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libsystemd0-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsystemd0-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsystemd0-mini-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsystemd0-mini-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libudev-devel-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libudev-mini-devel-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libudev-mini1-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libudev-mini1-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libudev1-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libudev1-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nss-myhostname-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nss-myhostname-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nss-mymachines-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nss-mymachines-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nss-systemd-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nss-systemd-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-bash-completion-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-container-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-container-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-coredump-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-coredump-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-debugsource-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-devel-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-logger-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-mini-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-mini-bash-completion-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-mini-container-mini-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-mini-container-mini-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-mini-coredump-mini-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-mini-coredump-mini-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-mini-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-mini-debugsource-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-mini-devel-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-mini-sysvinit-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"systemd-sysvinit-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"udev-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"udev-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"udev-mini-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"udev-mini-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsystemd0-32bit-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsystemd0-32bit-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libudev-devel-32bit-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libudev1-32bit-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libudev1-32bit-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"nss-myhostname-32bit-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"nss-myhostname-32bit-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"nss-mymachines-32bit-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"nss-mymachines-32bit-debuginfo-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"systemd-32bit-234-lp151.26.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"systemd-32bit-debuginfo-234-lp151.26.7.1") ) flag++;

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
