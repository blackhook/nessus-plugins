#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-117.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106548);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15908", "CVE-2018-1049");

  script_name(english:"openSUSE Security Update : systemd (openSUSE-2018-117)");
  script_summary(english:"Check for the openSUSE-2018-117 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd fixes several issues.

This security issue was fixed :

  - CVE-2018-1049: Prevent race that can lead to DoS when
    using automounts (bsc#1076308).

These non-security issues were fixed :

  - core: don't choke if a unit another unit triggers
    vanishes during reload

  - delta: don't ignore PREFIX when the given argument is
    PREFIX/SUFFIX

  - delta: extend skip logic to work on full directory paths
    (prefix+suffix) (bsc#1070428)

  - delta: check if a prefix needs to be skipped only once

  - delta: skip symlink paths when split-usr is enabled
    (#4591)

  - sysctl: use raw file descriptor in sysctl_write (#7753)

  - sd-netlink: don't take possesion of netlink fd from
    caller on failure (bsc#1074254)

  - Fix the regexp used to detect broken by-id symlinks in
    /etc/crypttab It was missing the following case:
    '/dev/disk/by-id/cr_-xxx'.

  - sysctl: disable buffer while writing to /proc
    (bsc#1071558)

  - Use read_line() and LONG_LINE_MAX to read values
    configuration files. (bsc#1071558)

  - sysctl: no need to check for eof twice

  - def: add new constant LONG_LINE_MAX

  - fileio: add new helper call read_line() as bounded
    getline() replacement

  - service: Don't stop unneeded units needed by restarted
    service (#7526) (bsc#1066156)

  - gpt-auto-generator: fix the handling of the value
    returned by fstab_has_fstype() in add_swap() (#6280)

  - gpt-auto-generator: disable gpt auto logic for swaps if
    at least one is defined in fstab (bsc#897422)

  - fstab-util: introduce fstab_has_fstype() helper

  - fstab-generator: ignore root=/dev/nfs (#3591)

  - fstab-generator: don't process root= if it happens to be
    'gpt-auto' (#3452)

  - virt: use XENFEAT_dom0 to detect the hardware domain
    (#6442, #6662) (#7581) (bsc#1048510)

  - analyze: replace --no-man with --man=no in the man page
    (bsc#1068251)

  - udev: net_setup_link: don't error out when we couldn't
    apply link config (#7328)

  - Add missing /etc/systemd/network directory

  - Fix parsing of features in detect_vm_xen_dom0 (#7890)
    (bsc#1048510)

  - sd-bus: use -- when passing arguments to ssh (#6706)

  - systemctl: make sure we terminate the bus connection
    first, and then close the pager (#3550)

  - sd-bus: bump message queue size (bsc#1075724)

  - tmpfiles: downgrade warning about duplicate line

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=897422"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-debuginfo-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-mini-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsystemd0-mini-debuginfo-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-devel-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini-devel-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini1-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev-mini1-debuginfo-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev1-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libudev1-debuginfo-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-myhostname-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-myhostname-debuginfo-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-mymachines-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nss-mymachines-debuginfo-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-bash-completion-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-debuginfo-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-debugsource-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-devel-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-logger-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-bash-completion-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-debuginfo-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-debugsource-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-devel-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-mini-sysvinit-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"systemd-sysvinit-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-debuginfo-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-mini-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"udev-mini-debuginfo-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsystemd0-32bit-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libudev1-32bit-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"nss-myhostname-32bit-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"nss-myhostname-debuginfo-32bit-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"systemd-32bit-228-41.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-41.1") ) flag++;

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
