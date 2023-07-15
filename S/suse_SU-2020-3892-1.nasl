#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3892-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(144535);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/24");

  script_cve_id("CVE-2020-27745", "CVE-2020-27746");

  script_name(english:"SUSE SLES12 Security Update : slurm_20_02 (SUSE-SU-2020:3892-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for slurm_20_02 fixes the following issues :

Security issues fixed :

CVE-2020-27745: Fixed a potential buffer overflow from use of
unpackmem (bsc#1178890).

CVE-2020-27746: Fixed a potential leak of the magic cookie when sent
as an argument to the xauth command (bsc#1178891).

Non-security issues fixed :

Updated to 20.02.6. Full log and details available at :

  - https://lists.schedmd.com/pipermail/slurm-announce/2020/000045.html

Updated to 20.02.5, changes :

  - Fix leak of TRESRunMins when job time is changed with
    --time-min

  - pam_slurm - explicitly initialize slurm config to
    support configless mode.

  - scontrol - Fix exit code when creating/updating
    reservations with wrong Flags.

  - When a GRES has a no_consume flag, report 0 for
    allocated.

  - Fix cgroup cleanup by jobacct_gather/cgroup.

  - When creating reservations/jobs don't allow counts on a
    feature unless using an XOR.

  - Improve number of boards discovery

  - Fix updating a reservation NodeCnt on a zero-count
    reservation.

  - slurmrestd - provide an explicit error messages when PSK
    auth fails.

  - cons_tres - fix job requesting single gres per-node
    getting two or more nodes with less CPUs than requested
    per-task.

  - cons_tres - fix calculation of cores when using gres and
    cpus-per-task.

  - cons_tres - fix job not getting access to socket without
    GPU or with less than --gpus-per-socket when not enough
    cpus available on required socket and not using
    --gres-flags=enforce binding.

  - Fix HDF5 type version build error.

  - Fix creation of CoreCnt only reservations when the first
    node isn't available.

  - Fix wrong DBD Agent queue size in sdiag when using
    accounting_storage/none.

  - Improve job constraints XOR option logic.

  - Fix preemption of hetjobs when needed nodes not in
    leader component.

  - Fix wrong bit_or() messing potential preemptor jobs node
    bitmap, causing bad node deallocations and even
    allocation of nodes from other partitions.

  - Fix double-deallocation of preempted non-leader hetjob
    components.

  - slurmdbd - prevent truncation of the step nodelists over
    4095.

  - Fix nodes remaining in drain state state after rebooting
    with ASAP option.

  - changes from 20.02.4 :

  - srun - suppress job step creation warning message when
    waiting on PrologSlurmctld.

  - slurmrestd - fix incorrect return values in
    data_list_for_each() functions.

  - mpi/pmix - fix issue where HetJobs could fail to launch.

  - slurmrestd - set content-type header in responses.

  - Fix cons_res GRES overallocation for
    --gres-flags=disable-binding.

  - Fix cons_res incorrectly filtering cores with respect to
    GRES locality for

    --gres-flags=disable-binding requests.

  - Fix regression where a dependency on multiple jobs in a
    single array using underscores would only add the first
    job.

  - slurmrestd - fix corrupted output due to incorrect use
    of memcpy().

  - slurmrestd - address a number of minor Coverity
    warnings.

  - Handle retry failure when slurmstepd is communicating
    with srun correctly.

  - Fix jobacct_gather possibly duplicate stats when
    _is_a_lwp error shows up.

  - Fix tasks binding to GRES which are closest to the
    allocated CPUs.

  - Fix AMD GPU ROCM 3.5 support.

  - Fix handling of job arrays in sacct when querying
    specific steps.

  - slurmrestd - avoid fallback to local socket
    authentication if JWT authentication is ill-formed.

  - slurmrestd - restrict ability of requests to use
    different authentication plugins.

  - slurmrestd - unlink named unix sockets before closing.

  - slurmrestd - fix invalid formatting in openapi.json.

  - Fix batch jobs stuck in CF state on FrontEnd mode.

  - Add a separate explicit error message when rejecting
    changes to active node features.

  - cons_common/job_test - fix slurmctld SIGABRT due to
    double-free.

  - Fix updating reservations to set the duration correctly
    if updating the start time.

  - Fix update reservation to promiscuous mode.

  - Fix override of job tasks count to max when
    ntasks-per-node present.

  - Fix min CPUs per node not being at least CPUs per task
    requested.

  - Fix CPUs allocated to match CPUs requested when
    requesting GRES and threads per core equal to one.

  - Fix NodeName config parsing with Boards and without
    CPUs.

  - Ensure SLURM_JOB_USER and SLURM_JOB_UID are set in
    SrunProlog/Epilog.

  - Fix error messages for certain invalid
    salloc/sbatch/srun options.

  - pmi2 - clean up sockets at step termination.

  - Fix 'scontrol hold' to work with 'JobName'.

  - sbatch - handle --uid/--gid in #SBATCH directives
    properly.

  - Fix race condition in job termination on slurmd.

  - Print specific error messages if trying to run use
    certain priority/multifactor factors that cannot work
    without SlurmDBD.

  - Avoid partial GRES allocation when --gpus-per-job is not
    satisfied.

  - Cray - Avoid referencing a variable outside of it's
    correct scope when dealing with creating steps within a
    het job.

  - slurmrestd - correctly handle larger addresses from
    accept().

  - Avoid freeing wrong pointer with
    SlurmctldParameters=max_dbd_msg_action with another
    option after that.

  - Restore MCS label when suspended job is resumed.

  - Fix insufficient lock levels.

  - slurmrestd - use errno from job submission.

  - Fix 'user' filter for sacctmgr show transactions.

  - Fix preemption logic.

  - Fix no_consume GRES for exclusive (whole node) requests.

  - Fix regression in 20.02 that caused an infinite loop in
    slurmctld when requesting --distribution=plane for the
    job.

  - Fix parsing of the --distribution option.

  - Add CONF READ_LOCK to _handle_fed_send_job_sync.

  - prep/script - always call slurmctld PrEp callback in
    _run_script().

  - Fix node estimation for jobs that use GPUs or
    --cpus-per-task.

  - Fix jobcomp, job_submit and cli_filter Lua
    implementation plugins causing slurmctld and/or job
    submission CLI tools segfaults due to bad return
    handling when the respective Lua script failed to load.

  - Fix propagation of gpu options through hetjob
    components.

  - Add SLURM_CLUSTERS environment variable to scancel.

  - Fix packing/unpacking of 'unlinked' jobs.

  - Connect slurmstepd's stderr to srun for steps launched
    with --pty.

  - Handle MPS correctly when doing exclusive allocations.

  - slurmrestd - fix compiling against libhttpparser in a
    non-default path.

  - slurmrestd - avoid compilation issues with libhttpparser
    < 2.6.

  - Fix compile issues when compiling slurmrestd without
    --enable-debug.

  - Reset idle time on a reservation that is getting purged.

  - Fix reoccurring reservations that have Purge_comp= to
    keep correct duration if they are purged.

  - scontrol - changed the 'PROMISCUOUS' flag to 'MAGNETIC'

  - Early return from epilog_set_env in case of no_consume.

  - Fix cons_common/job_test start time discovery logic to
    prevent skewed results between 'will run test'
    executions.

  - Ensure TRESRunMins limits are maintained during
    'scontrol reconfigure'.

  - Improve error message when host lookup fails.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.schedmd.com/pipermail/slurm-announce/2020/000045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27745/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27746/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203892-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44c01572"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for HPC 12 :

zypper in -t patch SUSE-SLE-Module-HPC-12-2020-3892=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnss_slurm2_20_02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnss_slurm2_20_02-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0_20_02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0_20_02-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm35-debuginfo");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libnss_slurm2_20_02-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libnss_slurm2_20_02-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libpmi0_20_02-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libpmi0_20_02-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libslurm35-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libslurm35-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"perl-slurm_20_02-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"perl-slurm_20_02-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-auth-none-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-auth-none-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-config-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-config-man-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-debugsource-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-devel-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-doc-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-lua-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-lua-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-munge-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-munge-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-node-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-node-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-pam_slurm-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-pam_slurm-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-plugins-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-plugins-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-slurmdbd-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-slurmdbd-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-sql-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-sql-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-sview-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-sview-debuginfo-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-torque-20.02.6-3.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_02-torque-debuginfo-20.02.6-3.8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "slurm_20_02");
}
