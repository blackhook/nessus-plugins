#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-806.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101516);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-9217");

  script_name(english:"openSUSE Security Update : systemd (openSUSE-2017-806)");
  script_summary(english:"Check for the openSUSE-2017-806 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd fixes the following issues :

Security issue fixed :

  - CVE-2017-9217: resolved: Fix NULL pointer p->question
    dereferencing that could lead to resolved aborting
    (bsc#1040614)

The update also fixed several non-security bugs :

  - core/mount: Use the '-c' flag to not canonicalize paths
    when calling /bin/umount

  - automount: Handle expire_tokens when the mount unit
    changes its state (bsc#1040942)

  - automount: Rework propagation between automount and
    mount units

  - build: Make sure tmpfiles.d/systemd-remote.conf get
    installed when necessary

  - build: Fix systemd-journal-upload installation

  - basic: Detect XEN Dom0 as no virtualization
    (bsc#1036873)

  - virt: Make sure some errors are not ignored

  - fstab-generator: Do not skip Before= ordering for noauto
    mountpoints

  - fstab-gen: Do not convert device timeout into seconds
    when initializing JobTimeoutSec

  - core/device: Use JobRunningTimeoutSec= for device units
    (bsc#1004995)

  - fstab-generator: Apply the _netdev option also to device
    units (bsc#1004995)

  - job: Add JobRunningTimeoutSec for JOB_RUNNING state
    (bsc#1004995)

  - job: Ensure JobRunningTimeoutSec= survives serialization
    (bsc#1004995)

  - rules: Export NVMe WWID udev attribute (bsc#1038865)

  - rules: Introduce disk/by-id (model_serial) symbolic
    links for NVMe drives

  - rules: Add rules for NVMe devices

  - sysusers: Make group shadow support configurable
    (bsc#1029516)

  - core: When deserializing a unit, fully restore its
    cgroup state (bsc#1029102)

  - core: Introduce
    cg_mask_from_string()/cg_mask_to_string()

  - core:execute: Fix handling failures of calling fork() in
    exec_spawn() (bsc#1040258)

  - Fix systemd-sysv-convert when a package starts shipping
    service units (bsc#982303) The database might be missing
    when upgrading a package which was shipping no sysv init
    scripts nor unit files (at the time --save was called)
    but the new version start shipping unit files.

  - Disable group shadow support (bsc#1029516)

  - Only check signature job error if signature job exists
    (bsc#1043758)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982303"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libsystemd0-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsystemd0-debuginfo-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsystemd0-mini-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsystemd0-mini-debuginfo-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libudev-devel-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libudev-mini-devel-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libudev-mini1-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libudev-mini1-debuginfo-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libudev1-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libudev1-debuginfo-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nss-myhostname-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nss-myhostname-debuginfo-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nss-mymachines-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nss-mymachines-debuginfo-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-bash-completion-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-debuginfo-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-debugsource-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-devel-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-logger-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-mini-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-mini-bash-completion-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-mini-debuginfo-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-mini-debugsource-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-mini-devel-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-mini-sysvinit-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"systemd-sysvinit-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"udev-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"udev-debuginfo-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"udev-mini-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"udev-mini-debuginfo-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsystemd0-32bit-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libudev1-32bit-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"nss-myhostname-32bit-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"nss-myhostname-debuginfo-32bit-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"systemd-32bit-228-25.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-25.6.1") ) flag++;

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
