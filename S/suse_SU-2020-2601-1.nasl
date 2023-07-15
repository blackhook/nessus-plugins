#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2601-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(140514);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2019-19727", "CVE-2020-1269", "CVE-2020-12693");

  script_name(english:"SUSE SLES12 Security Update : slurm (SUSE-SU-2020:2601-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for slurm fixes the following issues :

Fix Authentication Bypass when Message Aggregation is enabled
CVE-2020-12693 This fixes and issue where authentication could be
bypassed via an alternate path or channel when message Aggregation was
enabled. A race condition allowed a user to launch a process as an
arbitrary user. Add :

Fix-Authentication-Bypass-when-Message-Aggregation-is-enabled-CVE-2020
-1269 3.patch (CVE-2020-12693, bsc#1172004).

Remove unneeded build dependency to postgresql-devel.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19727/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12693/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202601-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0323721");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for HPC 12 :

zypper in -t patch SUSE-SLE-Module-HPC-12-2020-2601=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1269");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-12693");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm31-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-auth-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-auth-none-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-munge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-munge-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-pam_slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-pam_slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sched-wiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-slurmdb-direct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-slurmdbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-torque-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libpmi0-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libpmi0-debuginfo-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libslurm31-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libslurm31-debuginfo-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"perl-slurm-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"perl-slurm-debuginfo-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-auth-none-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-auth-none-debuginfo-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-config-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-debuginfo-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-debugsource-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-devel-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-doc-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-lua-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-lua-debuginfo-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-munge-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-munge-debuginfo-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-pam_slurm-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-pam_slurm-debuginfo-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-plugins-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-plugins-debuginfo-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-sched-wiki-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-slurmdb-direct-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-slurmdbd-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-slurmdbd-debuginfo-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-sql-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-sql-debuginfo-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-torque-17.02.11-6.44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-torque-debuginfo-17.02.11-6.44.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "slurm");
}
