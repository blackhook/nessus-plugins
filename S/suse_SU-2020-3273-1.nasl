#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3273-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143629);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-25656", "CVE-2020-8694");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : kernel (SUSE-SU-2020:3273-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various
security and bug fixes.

The following security bugs were fixed :

CVE-2020-25656: Fixed a concurrency use-after-free in
vt_do_kdgkb_ioctl (bnc#1177766).

CVE-2020-8694: Restricted energy meter to root access (bsc#1170415).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1163592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1164648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1170415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1175749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1176354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25656/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-8694/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203273-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24bc19d5"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15-SP2 :

zypper in -t patch SUSE-SLE-Product-WE-15-SP2-2020-3273=1

SUSE Linux Enterprise Module for Live Patching 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Live-Patching-15-SP2-2020-3273=1

SUSE Linux Enterprise Module for Legacy Software 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Legacy-15-SP2-2020-3273=1

SUSE Linux Enterprise Module for Development Tools 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP2-2020-3273=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2020-3273=1

SUSE Linux Enterprise High Availability 15-SP2 :

zypper in -t patch SUSE-SLE-Product-HA-15-SP2-2020-3273=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-debuginfo-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-debugsource-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-devel-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-devel-debuginfo-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-base-5.3.18-24.37.1.9.13.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-debuginfo-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-debugsource-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-devel-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-default-devel-debuginfo-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-obs-build-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-obs-build-debugsource-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"kernel-syms-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"reiserfs-kmp-default-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"reiserfs-kmp-default-debuginfo-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-debuginfo-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-debugsource-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-devel-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"kernel-preempt-devel-debuginfo-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-base-5.3.18-24.37.1.9.13.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-debuginfo-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-debugsource-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-devel-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-default-devel-debuginfo-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-obs-build-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-obs-build-debugsource-5.3.18-24.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"kernel-syms-5.3.18-24.37.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
