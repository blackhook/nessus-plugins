#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2607-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143870);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2016-10030",
    "CVE-2017-15566",
    "CVE-2018-7033",
    "CVE-2018-10995",
    "CVE-2019-6438",
    "CVE-2019-12838",
    "CVE-2019-19727",
    "CVE-2019-19728",
    "CVE-2020-12693"
  );

  script_name(english:"SUSE SLES12 Security Update : pdsh, slurm_20_02 (SUSE-SU-2020:2607-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for pdsh, slurm_20_02 fixes the following issues :

Changes in slurm_20_02 :

Add support for openPMIx also for Leap/SLE 15.0/1 (bsc#1173805).

Do not run %check on SLE-12-SP2: Some incompatibility in tcl makes
this fail.

Remove unneeded build dependency to postgresql-devel.

Disable build on s390 (requires 64bit).

Bring QA to the package build: add %%check stage.

Remove cruft that isn't needed any longer.

Add 'ghosted' run-file.

Add rpmlint filter to handle issues with library packages for Leap and
enterprise upgrade versions.

Updated to 20.02.3 which fixes CVE-2020-12693 (bsc#1172004).

Other changes are :

  - Factor in ntasks-per-core=1 with cons_tres.

  - Fix formatting in error message in cons_tres.

  - Fix calling stat on a NULL variable.

  - Fix minor memory leak when using reservations with
    flags=first_cores.

  - Fix gpu bind issue when CPUs=Cores and ThreadsPerCore >
    1 on a node.

  - Fix --mem-per-gpu for heterogenous --gres requests.

  - Fix slurmctld load order in load_all_part_state().

  - Fix race condition not finding jobacct gather task
    cgroup entry.

  - Suppress error message when selecting nodes on disjoint
    topologies.

  - Improve performance of _pack_default_job_details() with
    large number of job

  - arguments.

  - Fix archive loading previous to 17.11 jobs per-node
    req_mem.

  - Fix regresion validating that --gpus-per-socket requires

    --sockets-per-node

  - for steps. Should only validate allocation requests.

  - error() instead of fatal() when parsing an invalid
    hostlist.

  - nss_slurm - fix potential deadlock in slurmstepd on
    overloaded systems.

  - cons_tres - fix --gres-flags=enforce-binding and related

    --cpus-per-gres.

  - cons_tres - Allocate lowest numbered cores when
    filtering cores with gres.

  - Fix getting system counts for named GRES/TRES.

  - MySQL - Fix for handing typed GRES for association
    rollups.

  - Fix step allocations when tasks_per_core > 1.

  - Fix allocating more GRES than requested when asking for
    multiple GRES types.

Treat libnss_slurm like any other package: add version string to
upgrade package.

Updated to 20.02.1 with following changes'

  - Improve job state reason for jobs hitting
    partition_job_depth.

  - Speed up testing of singleton dependencies.

  - Fix negative loop bound in cons_tres.

  - srun - capture the MPI plugin return code from
    mpi_hook_client_fini() and use as final return code for
    step failure.

  - Fix segfault in cli_filter/lua.

  - Fix --gpu-bind=map_gpu reusability if tasks > elements.

  - Make sure config_flags on a gres are sent to the
    slurmctld on node registration.

  - Prolog/Epilog - Fix missing GPU information.

  - Fix segfault when using config parser for expanded
    lines.

  - Fix bit overlap test function.

  - Don't accrue time if job begin time is in the future.

  - Remove accrue time when updating a job start/eligible
    time to the future.

  - Fix regression in 20.02.0 that broke --depend=expand.

  - Reset begin time on job release if it's not in the
    future.

  - Fix for recovering burst buffers when using
    high-availability.

  - Fix invalid read due to freeing an incorrectly allocated
    env array.

  - Update slurmctld -i message to warn about losing data.

  - Fix scontrol cancel_reboot so it clears the DRAIN flag
    and node reason for a pending ASAP reboot.

Changes in pdsh: Bring QA to the package build: add %%check stage

Since the build for the SLE-12 HPC Module got fixed, simplify spec
file and remove legacy workarounds.

Remove _multibuild file where not needed.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1007053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1018371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1031872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1041706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1065697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1084125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1084917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1085240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1085606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1086859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1088693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1090292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1095508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1100850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1103561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1108671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1109373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1116758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1123304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1140709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1153095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1153259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1155784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1161716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1164326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1164386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-10030/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-15566/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10995/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-7033/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12838/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19727/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19728/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-6438/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12693/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202607-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8522e9c3");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for HPC 12 :

zypper in -t patch SUSE-SLE-Module-HPC-12-2020-2607=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10030");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-6438");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnss_slurm2_20_02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnss_slurm2_20_02-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0_20_02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0_20_02-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm35-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-slurm_18_08");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-slurm_18_08-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-slurm_20_02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-slurm_20_02-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm_20_02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm_20_02-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-auth-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-auth-none-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-config-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-munge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-munge-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-node-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-pam_slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-pam_slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-slurmdbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-sview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-sview-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_02-torque-debuginfo");
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
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libnss_slurm2_20_02-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libnss_slurm2_20_02-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libpmi0_20_02-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libpmi0_20_02-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libslurm35-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libslurm35-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-slurm_18_08-2.34-7.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-slurm_18_08-debuginfo-2.34-7.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-slurm_20_02-2.34-7.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-slurm_20_02-debuginfo-2.34-7.26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"perl-slurm_20_02-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"perl-slurm_20_02-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-auth-none-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-auth-none-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-config-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-config-man-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-debugsource-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-devel-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-doc-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-lua-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-lua-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-munge-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-munge-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-node-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-node-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-pam_slurm-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-pam_slurm-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-plugins-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-plugins-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-slurmdbd-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-slurmdbd-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-sql-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-sql-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-sview-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-sview-debuginfo-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-torque-20.02.3-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-torque-debuginfo-20.02.3-3.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pdsh / slurm_20_02");
}
