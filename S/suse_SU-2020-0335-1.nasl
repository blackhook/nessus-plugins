#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0335-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(133540);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-20386", "CVE-2020-1712");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : systemd (SUSE-SU-2020:0335-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for systemd fixes the following issues :

CVE-2020-1712 (bsc#bsc#1162108) Fix a heap use-after-free
vulnerability, when asynchronous Polkit queries were performed while
handling Dbus messages. A local unprivileged attacker could have
abused this flaw to crash systemd services or potentially execute code
and elevate their privileges, by sending specially crafted Dbus
messages.

Use suse.pool.ntp.org server pool on SLE distros (jsc#SLE-7683)

libblkid: open device in nonblock mode. (bsc#1084671)

udev/cdrom_id: Do not open CD-rom in exclusive mode. (bsc#1154256)

bus_open leak sd_event_source when udevadm
trigger&Atilde;&pound;&Acirc;&#128;&Acirc;&#130; (bsc#1161436
CVE-2019-20386)

fileio: introduce read_full_virtual_file() for reading virtual files
in sysfs, procfs (bsc#1133495 bsc#1159814)

fileio: initialize errno to zero before we do fread()

fileio: try to read one byte too much in read_full_stream()

logind: consider 'greeter' sessions suitable as 'display' sessions of
a user (bsc#1158485)

logind: never elect a session that is stopping as display

journal: include kmsg lines from the systemd process which exec()d us
(#8078)

udevd: don't use monitor after manager_exit()

udevd: capitalize log messages in on_sigchld()

udevd: merge conditions to decrease indentation

Revert 'udevd: fix crash when workers time out after exit is signal
caught'

core: fragments of masked units ought not be considered for
NeedDaemonReload (#7060) (bsc#1156482)

udevd: fix crash when workers time out after exit is signal caught

udevd: wait for workers to finish when exiting (bsc#1106383)

Improve bash completion support (bsc#1155207)

  - shell-completion: systemctl: do not list template units
    in {re,}start

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

networkd: VXLan Make group and remote variable separate (bsc#1156213)

networkd: vxlan require Remote= to be a non multicast address (#8117)
(bsc#1156213)

fs-util: let's avoid unnecessary strerror()

fs-util: introduce inotify_add_watch_and_warn() helper

ask-password: improve log message when inotify limit is reached
(bsc#1155574)

shared/install: failing with -ELOOP can be due to the use of an alias
in install_error() (bsc#1151377)

man: alias names can't be used with enable command (bsc#1151377)

Add boot option to not use swap at system start (jsc#SLE-7689)

Allow YaST to select Iranian (Persian, Farsi) keyboard layout
(bsc#1092920)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1084671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1159814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1161436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1162108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-20386/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-1712/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200335-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f396f04"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-335=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-335=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-335=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15 :

zypper in -t patch SUSE-SLE-Module-Development-Tools-OBS-15-2020-335=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-335=1

SUSE Linux Enterprise Module for Basesystem 15 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-2020-335=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-335=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-335=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1712");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-mini1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-mini1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-myhostname-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-myhostname-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-myhostname-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-mymachines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-mymachines-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-mymachines-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-mymachines-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-container-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-coredump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-coredump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-container-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-container-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-coredump-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-coredump-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-mini-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsystemd0-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsystemd0-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libudev-devel-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libudev1-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libudev1-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"nss-myhostname-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"nss-myhostname-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"nss-mymachines-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"nss-mymachines-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"systemd-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"systemd-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsystemd0-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsystemd0-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsystemd0-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsystemd0-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libudev-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libudev-mini-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libudev-mini1-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libudev-mini1-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libudev1-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libudev1-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nss-myhostname-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nss-myhostname-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nss-mymachines-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nss-mymachines-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nss-systemd-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nss-systemd-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-container-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-container-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-coredump-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-coredump-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-debugsource-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-logger-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-mini-container-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-mini-container-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-mini-coredump-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-mini-coredump-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-mini-debugsource-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-mini-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-mini-sysvinit-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"systemd-sysvinit-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"udev-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"udev-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"udev-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"udev-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsystemd0-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsystemd0-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libudev1-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libudev1-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"systemd-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"systemd-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsystemd0-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsystemd0-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsystemd0-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsystemd0-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev-mini-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev-mini1-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev-mini1-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev1-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev1-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-myhostname-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-myhostname-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-mymachines-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-mymachines-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-systemd-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-systemd-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-container-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-container-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-coredump-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-coredump-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-debugsource-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-logger-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-container-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-container-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-coredump-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-coredump-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-debugsource-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-sysvinit-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-sysvinit-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"udev-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"udev-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"udev-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"udev-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsystemd0-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsystemd0-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libudev-devel-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libudev1-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libudev1-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"nss-myhostname-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"nss-myhostname-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"nss-mymachines-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"nss-mymachines-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"systemd-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"systemd-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsystemd0-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsystemd0-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsystemd0-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsystemd0-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libudev-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libudev-mini-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libudev-mini1-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libudev-mini1-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libudev1-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libudev1-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nss-myhostname-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nss-myhostname-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nss-mymachines-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nss-mymachines-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nss-systemd-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nss-systemd-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-container-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-container-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-coredump-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-coredump-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-debugsource-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-logger-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-mini-container-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-mini-container-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-mini-coredump-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-mini-coredump-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-mini-debugsource-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-mini-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-mini-sysvinit-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"systemd-sysvinit-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"udev-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"udev-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"udev-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"udev-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsystemd0-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsystemd0-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libudev1-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libudev1-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"systemd-32bit-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"systemd-32bit-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsystemd0-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsystemd0-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsystemd0-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsystemd0-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev-mini-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev-mini1-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev-mini1-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev1-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev1-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-myhostname-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-myhostname-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-mymachines-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-mymachines-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-systemd-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-systemd-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-container-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-container-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-coredump-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-coredump-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-debugsource-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-logger-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-container-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-container-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-coredump-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-coredump-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-debugsource-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-devel-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-sysvinit-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-sysvinit-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"udev-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"udev-debuginfo-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"udev-mini-234-24.39.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"udev-mini-debuginfo-234-24.39.1")) flag++;


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
