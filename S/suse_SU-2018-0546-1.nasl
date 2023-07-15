#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0546-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(107022);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2017-18078");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : systemd (SUSE-SU-2018:0546-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for systemd fixes the following issues: Security issue
fixed :

  - CVE-2017-18078: tmpfiles: refuse to chown()/chmod()
    files which are hardlinked, unless protected_hardlinks
    sysctl is on. This could be used by local attackers to
    gain privileges (bsc#1077925) Non Security issues 
fixed :

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
    Public NTP servers time{1..4}.google.com

  - Don't ship /usr/lib/systemd/system/tmp.mnt at all
    (bsc#1071224) But we still ship a copy in /var. Users
    who want to use tmpfs on /tmp are supposed to add a
    symlink in /etc/ pointing to the copy shipped in /var.
    To support the update path we automatically create the
    symlink if tmp.mount in use is located in /usr.

  - Enable systemd-networkd on Leap distros only
    (bsc#1071311)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1077925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18078/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180546-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed419b76"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-355=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2018-355=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2018-355=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-355=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-355=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-355=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2018-355=1

SUSE CaaS Platform ALL:zypper in -t patch SUSE-CAASP-ALL-2018-355=1

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2018-355=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-debuginfo-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-debuginfo-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-debuginfo-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-debugsource-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-sysvinit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"udev-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"udev-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsystemd0-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsystemd0-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsystemd0-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsystemd0-debuginfo-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libudev1-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libudev1-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libudev1-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libudev1-debuginfo-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-debuginfo-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-debugsource-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-sysvinit-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"udev-228-150.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"udev-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-debugsource-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-sysvinit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"udev-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"udev-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsystemd0-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsystemd0-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsystemd0-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libudev1-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libudev1-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libudev1-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"systemd-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"systemd-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"systemd-debuginfo-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"systemd-debugsource-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"systemd-sysvinit-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"udev-228-150.32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"udev-debuginfo-228-150.32.1")) flag++;


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
