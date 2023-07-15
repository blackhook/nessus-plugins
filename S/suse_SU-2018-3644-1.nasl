#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3644-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120157);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id("CVE-2018-15686", "CVE-2018-15688");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : systemd (SUSE-SU-2018:3644-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for systemd fixes the following issues :

Security issues fixed :

CVE-2018-15688: A buffer overflow vulnerability in the dhcp6 client of
systemd allowed a malicious dhcp6 server to overwrite heap memory in
systemd-networkd. (bsc#1113632)

CVE-2018-15686: A vulnerability in unit_deserialize of systemd allows
an attacker to supply arbitrary state across systemd re-execution via
NotifyAccess. This can be used to improperly influence systemd
execution and possibly lead to root privilege escalation.
(bsc#1113665)

Non security issues fixed: dhcp6: split assert_return() to be more
debuggable when hit

core: skip unit deserialization and move to the next one when
unit_deserialize() fails

core: properly handle deserialization of unknown unit types (#6476)

core: don't create Requires for workdir if 'missing ok' (bsc#1113083)

logind: use manager_get_user_by_pid() where appropriate

logind: rework manager_get_{user|session}_by_pid() a bit

login: fix user@.service case, so we don't allow nested sessions
(#8051) (bsc#1112024)

core: be more defensive if we can't determine per-connection socket
peer (#7329)

core: introduce systemd.early_core_pattern= kernel cmdline option

core: add missing 'continue' statement

core/mount: fstype may be NULL

journald: don't ship systemd-journald-audit.socket (bsc#1109252)

core: make 'tmpfs' dependencies on swapfs a 'default' dep, not an
'implicit' (bsc#1110445)

mount: make sure we unmount tmpfs mounts before we deactivate swaps
(#7076)

detect-virt: do not try to read all of /proc/cpuinfo (bsc#1109197)

emergency: make sure console password agents don't interfere with the
emergency shell

man: document that 'nofail' also has an effect on ordering

journald: take leading spaces into account in syslog_parse_identifier

journal: do not remove multiple spaces after identifier in syslog
message

syslog: fix segfault in syslog_parse_priority()

journal: fix syslog_parse_identifier()

install: drop left-over debug message (#6913)

Ship systemd-sysv-install helper via the main package This script was
part of systemd-sysvinit sub-package but it was wrong since
systemd-sysv-install is a script used to redirect enable/disable
operations to chkconfig when the unit targets are sysv init scripts.
Therefore it's never been a SySV init tool.

Add udev.no-partlabel-links kernel command-line option. This option
can be used to disable the generation of the by-partlabel symlinks
regardless of the name used. (bsc#1089761)

man: SystemMaxUse= clarification in journald.conf(5). (bsc#1101040)

systemctl: load unit if needed in 'systemctl is-active' (bsc#1102908)

core: don't freeze OnCalendar= timer units when the clock goes back a
lot (bsc#1090944)

Enable or disable machines.target according to the presets
(bsc#1107941)

cryptsetup: add support for sector-size= option (fate#325697)

nspawn: always use permission mode 555 for /sys (bsc#1107640)

Bugfix for a race condition between daemon-reload and other commands
(bsc#1105031)

Fixes an issue where login with root credentials was not possible in
init level 5 (bsc#1091677)

Fix an issue where services of type 'notify' harmless DENIED log
entries. (bsc#991901)

Does no longer adjust qgroups on existing subvolumes (bsc#1093753)

cryptsetup: add support for sector-size= option (#9936) (fate#325697
bsc#1114135)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1089761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1093753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1102908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1110445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=991901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15686/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15688/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183644-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39c656f2"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2018-2595=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2018-2595=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15686");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-mini1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-mini1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-myhostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-myhostname-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nss-mymachines");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsystemd0-32bit-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsystemd0-32bit-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libudev1-32bit-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libudev1-32bit-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"systemd-32bit-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"systemd-32bit-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsystemd0-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsystemd0-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsystemd0-mini-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsystemd0-mini-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev-devel-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev-mini-devel-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev-mini1-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev-mini1-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev1-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudev1-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-myhostname-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-myhostname-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-mymachines-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-mymachines-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-systemd-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nss-systemd-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-container-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-container-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-coredump-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-coredump-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-debugsource-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-devel-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-logger-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-container-mini-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-container-mini-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-coredump-mini-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-coredump-mini-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-debugsource-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-devel-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-mini-sysvinit-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"systemd-sysvinit-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"udev-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"udev-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"udev-mini-234-24.15.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"udev-mini-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsystemd0-32bit-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsystemd0-32bit-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libudev1-32bit-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libudev1-32bit-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"systemd-32bit-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"systemd-32bit-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsystemd0-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsystemd0-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsystemd0-mini-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsystemd0-mini-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev-devel-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev-mini-devel-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev-mini1-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev-mini1-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev1-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudev1-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-myhostname-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-myhostname-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-mymachines-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-mymachines-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-systemd-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nss-systemd-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-container-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-container-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-coredump-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-coredump-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-debugsource-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-devel-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-logger-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-container-mini-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-container-mini-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-coredump-mini-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-coredump-mini-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-debugsource-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-devel-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-mini-sysvinit-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"systemd-sysvinit-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"udev-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"udev-debuginfo-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"udev-mini-234-24.15.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"udev-mini-debuginfo-234-24.15.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
