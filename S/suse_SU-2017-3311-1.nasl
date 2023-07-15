#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:3311-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120011);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-15566");

  script_name(english:"SUSE SLES12 Security Update : slurm (SUSE-SU-2017:3311-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for slurm fixes the following issues: Slurm was updated to
17.02.9 to fix a security bug, bringing new features and bugfixes
(fate#323998 bsc#1067580). Security issue fixed :

  - CVE-2017-15566: Fix security issue in Prolog and Epilog
    by always prepending SPANK_ to all user-set environment
    variables. (bsc#1065697) Changes in 17.02.9 :

  - When resuming powered down nodes, mark DOWN nodes right
    after ResumeTimeout has been reached (previous logic
    would wait about one minute longer).

  - Fix sreport not showing full column name for TRES Count.

  - Fix slurmdb_reservations_get() giving wrong usage data
    when job's spanned reservation that was modified.

  - Fix sreport reservation utilization report showing bad
    data.

  - Show all TRES' on a reservation in sreport reservation
    utilization report by default.

  - Fix sacctmgr show reservation handling 'end' parameter.

  - Work around issue with sysmacros.h and gcc7 / glibc
    2.25.

  - Fix layouts code to only allow setting a boolean.

  - Fix sbatch --wait to keep waiting even if a message
    timeout occurs.

  - CRAY - If configured with NodeFeatures=knl_cray and
    there are non-KNL nodes which include no features the
    slurmctld will abort without this patch when attemping
    strtok_r(NULL).

  - Fix regression in 17.02.7 which would run the
    spank_task_privileged as part of the slurmstepd instead
    of it's child process. Changes in 17.02.8 :

  - Add 'slurmdbd:' to the accounting plugin to notify
    message is from dbd instead of local.

  - mpi/mvapich - Buffer being only partially cleared. No
    failures observed.

  - Fix for job --switch option on dragonfly network.

  - In salloc with --uid option, drop supplementary groups
    before changing UID.

  - jobcomp/elasticsearch - strip any trailing slashes from
    JobCompLoc.

  - jobcomp/elasticsearch - fix memory leak when
    transferring generated buffer.

  - Prevent slurmstepd ABRT when parsing gres.conf CPUs.

  - Fix sbatch --signal to signal all MPI ranks in a step
    instead of just those on node 0.

  - Check multiple partition limits when scheduling a job
    that were previously only checked on submit.

  - Cray: Avoid running application/step Node Health Check
    on the external job step.

  - Optimization enhancements for partition based job
    preemption.

  - Address some build warnings from GCC 7.1, and one
    possible memory leak if /proc is inaccessible.

  - If creating/altering a core based reservation with
    scontrol/sview on a remote cluster correctly determine
    the select type.

  - Fix autoconf test for libcurl when clang is used.

  - Fix default location for
    cgroup_allowed_devices_file.conf to use correct default
    path.

  - Document NewName option to sacctmgr.

  - Reject a second PMI2_Init call within a single step to
    prevent slurmstepd from hanging.

  - Handle old 32bit values stored in the database for
    requested memory correctly in sacct.

  - Fix memory leaks in the task/cgroup plugin when
    constraining devices.

  - Make extremely verbose info messages debug2 messages in
    the task/cgroup plugin when constraining devices.

  - Fix issue that would deny the stepd access to /dev/null
    where GRES has a 'type' but no file defined.

  - Fix issue where the slurmstepd would fatal on job launch
    if you have no gres listed in your slurm.conf but some
    in gres.conf.

  - Fix validating time spec to correctly validate various
    time formats.

  - Make scontrol work correctly with job update timelimit
    [+|-]=.

  - Reduce the visibily of a number of warnings in
    _part_access_check.

  - Prevent segfault in sacctmgr if no association name is
    specified for an update command.

  - burst_buffer/cray plugin modified to work with changes
    in Cray UP05 software release.

  - Fix job reasons for jobs that are violating assoc
    MaxTRESPerNode limits.

  - Fix segfault when unpacking a 16.05 slurm_cred in a
    17.02 daemon.

  - Fix setting TRES limits with case insensitive TRES
    names.

  - Add alias for xstrncmp() -- slurm_xstrncmp().

  - Fix sorting of case insensitive strings when using
    xstrcasecmp().

  - Gracefully handle race condition when reading /proc as
    process exits.

  - Avoid error on Cray duplicate setup of core
    specialization.

  - Skip over undefined (hidden in Slurm) nodes in pbsnodes.

  - Add empty hashes in perl api's slurm_load_node() for
    hidden nodes.

  - CRAY - Add rpath logic to work for the alpscomm libs.

  - Fixes for administrator extended TimeLimit (job reason &
    time limit reset).

  - Fix gres selection on systems running select/linear.

  - sview: Added window decorator for
    maximize,minimize,close buttons for all systems.

  - squeue: interpret negative length format specifiers as a
    request to delimit values with spaces.

  - Fix the torque pbsnodes wrapper script to parse a gres
    field with a type set correctly. This update also
    contains pdsh rebuilt against the new libslurm version.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1007053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1041706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15566/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20173311-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94496308"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for HPC 12:zypper in -t patch
SUSE-SLE-Module-HPC-12-2017-2072=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm29");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm29-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm31-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-auth-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-auth-none-debuginfo");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libpmi0-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libpmi0-debuginfo-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libslurm29-16.05.8.1-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libslurm29-debuginfo-16.05.8.1-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libslurm31-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libslurm31-debuginfo-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-2.33-7.5.17")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-debuginfo-2.33-7.5.17")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-debugsource-2.33-7.5.17")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"perl-slurm-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"perl-slurm-debuginfo-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-auth-none-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-auth-none-debuginfo-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-debuginfo-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-debugsource-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-devel-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-doc-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-lua-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-lua-debuginfo-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-munge-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-munge-debuginfo-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-pam_slurm-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-pam_slurm-debuginfo-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-plugins-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-plugins-debuginfo-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-sched-wiki-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-slurmdb-direct-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-slurmdbd-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-slurmdbd-debuginfo-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-sql-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-sql-debuginfo-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-torque-17.02.9-6.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm-torque-debuginfo-17.02.9-6.10.1")) flag++;


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
