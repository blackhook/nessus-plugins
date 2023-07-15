#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3767-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(118965);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/31");

  script_cve_id("CVE-2018-15686", "CVE-2018-15688");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : systemd (SUSE-SU-2018:3767-1)");
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

Non-security issues fixed: dhcp6: split assert_return() to be more
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

socket-util: introduce port argument in sockaddr_port()

service: fixup ExecStop for socket-activated shutdown (#4120)

service: Continue shutdown on socket activated unit on termination
(#4108) (bsc#1106923)

cryptsetup: build fixes for 'add support for sector-size= option'

udev-rules: IMPORT cmdline does not recognize keys with similar names
(bsc#1111278)

core: keep the kernel coredump defaults when systemd-coredump is
disabled

core: shorten main() a bit, split out coredump initialization

core: set RLIMIT_CORE to unlimited by default (bsc#1108835)

core/mount: fstype may be NULL

journald: don't ship systemd-journald-audit.socket (bsc#1109252)

core: make 'tmpfs' dependencies on swapfs a 'default' dep, not an
'implicit' (bsc#1110445)

mount: make sure we unmount tmpfs mounts before we deactivate swaps
(#7076)

tmp.mount.hm4: After swap.target (#3087)

Ship systemd-sysv-install helper via the main package This script was
part of systemd-sysvinit sub-package but it was wrong since
systemd-sysv-install is a script used to redirect enable/disable
operations to chkconfig when the unit targets are sysv init scripts.
Therefore it's never been a SySV init tool.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1108835"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111278"
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
    value:"https://www.suse.com/security/cve/CVE-2018-15686/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15688/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183767-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e736a246"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-2659=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-2659=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-2659=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-2659=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-2659=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2018-2659=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-2659=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-2659=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2018-2659=1"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-debuginfo-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsystemd0-debuginfo-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-debuginfo-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libudev1-debuginfo-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-debuginfo-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-debuginfo-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-debugsource-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"systemd-sysvinit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"udev-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"udev-debuginfo-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsystemd0-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsystemd0-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsystemd0-debuginfo-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsystemd0-debuginfo-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libudev1-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libudev1-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libudev1-debuginfo-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libudev1-debuginfo-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-debuginfo-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-debuginfo-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-debugsource-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"systemd-sysvinit-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"udev-228-150.53.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"udev-debuginfo-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-debuginfo-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsystemd0-debuginfo-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-debuginfo-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-debuginfo-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-debuginfo-32bit-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-debugsource-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"systemd-sysvinit-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"udev-228-150.53.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"udev-debuginfo-228-150.53.3")) flag++;


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
