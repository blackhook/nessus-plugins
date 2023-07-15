#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0354-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(146366);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2020-25211",
    "CVE-2020-25639",
    "CVE-2020-27835",
    "CVE-2020-29568",
    "CVE-2020-29569",
    "CVE-2021-0342",
    "CVE-2021-3347",
    "CVE-2021-3348",
    "CVE-2021-20177"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : kernel (SUSE-SU-2021:0354-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

CVE-2021-3347: A use-after-free was discovered in the PI futexes
during fault handling, allowing local users to execute code in the
kernel (bnc#1181349).

CVE-2021-3348: Fixed a use-after-free in nbd_add_socket that could be
triggered by local attackers (with access to the nbd device) via an
I/O request at a certain point during device setup (bnc#1181504).

CVE-2021-20177: Fixed a kernel panic related to iptables string
matching rules. A privileged user could insert a rule which could lead
to denial of service (bnc#1180765).

CVE-2021-0342: In tun_get_user of tun.c, there is possible memory
corruption due to a use after free. This could lead to local
escalation of privilege with System execution privileges required.
(bnc#1180812)

CVE-2020-27835: A use-after-free in the infiniband hfi1 driver was
found, specifically in the way user calls Ioctl after open dev file
and fork. A local user could use this flaw to crash the system
(bnc#1179878).

CVE-2020-25639: Fixed a NULL pointer dereference via nouveau ioctl
(bnc#1176846).

CVE-2020-29569: Fixed a potential privilege escalation and information
leaks related to the PV block backend, as used by Xen (bnc#1179509).

CVE-2020-29568: Fixed a denial of service issue, related to processing
watch events (bnc#1179508).

CVE-2020-25211: Fixed a flaw where a local attacker was able to inject
conntrack netlink configuration that could cause a denial of service
or trigger the use of incorrect protocol numbers in
ctnetlink_parse_tuple_filter (bnc#1176395).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1065600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1153274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1155518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1163930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1165545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1167773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1175389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25211/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25639/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27835/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29568/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29569/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0342/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20177/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3347/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3348/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210354-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3438da4");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15-SP2 :

zypper in -t patch SUSE-SLE-Product-WE-15-SP2-2021-354=1

SUSE Linux Enterprise Module for Live Patching 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Live-Patching-15-SP2-2021-354=1

SUSE Linux Enterprise Module for Legacy Software 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Legacy-15-SP2-2021-354=1

SUSE Linux Enterprise Module for Development Tools 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Development-Tools-15-SP2-2021-354=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-354=1

SUSE Linux Enterprise High Availability 15-SP2 :

zypper in -t patch SUSE-SLE-Product-HA-15-SP2-2021-354=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3347");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-29569");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-debuginfo-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-debugsource-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-devel-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-devel-debuginfo-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-base-5.3.18-24.49.2.9.21.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-debuginfo-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-debugsource-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-devel-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-devel-debuginfo-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-obs-build-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-obs-build-debugsource-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-syms-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"reiserfs-kmp-default-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"reiserfs-kmp-default-debuginfo-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-debuginfo-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-debugsource-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-devel-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-devel-debuginfo-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-base-5.3.18-24.49.2.9.21.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-debuginfo-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-debugsource-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-devel-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-devel-debuginfo-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-obs-build-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-obs-build-debugsource-5.3.18-24.49.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-syms-5.3.18-24.49.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
