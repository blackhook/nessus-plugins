#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2031-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102188);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-9217", "CVE-2017-9445");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : systemd (SUSE-SU-2017:2031-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for systemd provides several fixes and enhancements.
Security issues fixed :

  - CVE-2017-9217: NULL pointer dereferencing that could
    lead to resolved aborting. (bsc#1040614)

  - CVE-2017-9445: Possible out-of-bounds write triggered by
    a specially crafted TCP payload from a DNS server.
    (bsc#1045290) The update also fixed several non-security
    bugs :

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
    scripts nor unit files (at the time

    --save was called) but the new version start shipping
    unit files.

  - Disable group shadow support (bsc#1029516)

  - Only check signature job error if signature job exists
    (bsc#1043758)

  - Automounter issue in combination with NFS volumes
    (bsc#1040968)

  - Missing symbolic link for SAS device in
    /dev/disk/by-path (bsc#1040153)

  - Add minimal support for boot.d/* scripts in
    systemd-sysv-convert (bsc#1046750)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1004995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1032029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1036873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=986216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9217/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9445/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172031-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2bed6f94"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-1245=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1245=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1245=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-debuginfo-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-debuginfo-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-debuginfo-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-debugsource-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-sysvinit-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"udev-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"udev-debuginfo-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-32bit-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-debuginfo-32bit-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-32bit-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-debuginfo-32bit-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-32bit-228-150.9.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-debuginfo-32bit-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-32bit-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-debuginfo-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-32bit-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-debuginfo-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-32bit-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-debuginfo-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-debugsource-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-sysvinit-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"udev-228-150.9.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"udev-debuginfo-228-150.9.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}