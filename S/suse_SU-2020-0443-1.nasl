#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0443-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(134036);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2016-10030",
    "CVE-2017-15566",
    "CVE-2018-7033",
    "CVE-2018-10995",
    "CVE-2019-6438",
    "CVE-2019-12838",
    "CVE-2019-19727",
    "CVE-2019-19728"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : pdsh, slurm_18_08 (SUSE-SU-2020:0443-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for pdsh, slurm_18_08 fixes the following issues :

Slurm was included in the 18.08 release, as 'slurm_18_08' package. The
version 18.08.9 contains all recent security fixes, including :

CVE-2019-19728: Fixed a privilege escalation with srun, where --uid
might have unintended side effects (bsc#1159692).

CVE-2019-19727: Fixed permissions of slurmdbd.conf (bsc#1155784).

pdsh was updated to: Add support for an alternative SLURM version when
building the slurm plugin.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1018371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1065697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1085240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1095508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1123304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1140709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1155784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-10030/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-15566/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10995/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-7033/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12838/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19727/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19728/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-6438/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200443-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5e4d795");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-443=1

SUSE Linux Enterprise Module for HPC 15-SP1:zypper in -t patch
SUSE-SLE-Module-HPC-15-SP1-2020-443=1

SUSE Linux Enterprise Module for HPC 15:zypper in -t patch
SUSE-SLE-Module-HPC-15-2020-443=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10030");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-6438");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0_18_08");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0_18_08-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm33");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm33-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-dshgroup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-dshgroup-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-genders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-genders-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-machines");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-machines-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-netgroup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-netgroup-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-slurm_18_08");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-slurm_18_08-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm_18_08");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm_18_08-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-auth-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-auth-none-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-munge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-munge-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-node-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-pam_slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-pam_slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-slurmdbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_18_08-torque-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-debugsource-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-dshgroup-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-dshgroup-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-genders-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-genders-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-machines-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-machines-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-netgroup-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-netgroup-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-slurm-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-slurm-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-slurm_18_08-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pdsh-slurm_18_08-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-debugsource-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-dshgroup-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-dshgroup-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-genders-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-genders-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-machines-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-machines-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-netgroup-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-netgroup-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-slurm-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-slurm-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-slurm_18_08-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"pdsh-slurm_18_08-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libpmi0_18_08-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libpmi0_18_08-debuginfo-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libslurm33-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libslurm33-debuginfo-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-debugsource-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-dshgroup-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-dshgroup-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-genders-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-genders-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-machines-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-machines-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-netgroup-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-netgroup-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-slurm-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-slurm-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-slurm_18_08-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"pdsh-slurm_18_08-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"perl-slurm_18_08-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"perl-slurm_18_08-debuginfo-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-auth-none-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-auth-none-debuginfo-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-config-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-debuginfo-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-debugsource-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-devel-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-doc-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-lua-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-lua-debuginfo-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-munge-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-munge-debuginfo-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-node-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-node-debuginfo-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-pam_slurm-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-pam_slurm-debuginfo-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-plugins-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-plugins-debuginfo-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-slurmdbd-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-slurmdbd-debuginfo-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-sql-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-sql-debuginfo-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-torque-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"slurm_18_08-torque-debuginfo-18.08.9-1.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-debugsource-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-dshgroup-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-dshgroup-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-genders-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-genders-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-machines-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-machines-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-netgroup-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-netgroup-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-slurm-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-slurm-debuginfo-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-slurm_18_08-2.33-7.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"pdsh-slurm_18_08-debuginfo-2.33-7.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pdsh / slurm_18_08");
}
