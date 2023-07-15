#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0773-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(147801);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2016-10030",
    "CVE-2017-15566",
    "CVE-2018-7033",
    "CVE-2018-10995",
    "CVE-2019-6438",
    "CVE-2019-12838",
    "CVE-2019-19727",
    "CVE-2019-19728",
    "CVE-2020-12693",
    "CVE-2020-27745",
    "CVE-2020-27746"
  );

  script_name(english:"SUSE SLES12 Security Update : slurm_20_11 / pdsh (SUSE-SU-2021:0773-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for pdsh fixes the following issues :

Preparing pdsh for Slurm 20.11 (jsc#ECO-2412)

Simplify convoluted condition.

This update for slurm fixes the following issues :

Fix potential buffer overflows from use of unpackmem(). CVE-2020-27745
(bsc#1178890)

Fix potential leak of the magic cookie when sent as an argument to the
xauth command. CVE-2020-27746 (bsc#1178891)

Add support for openPMIx also for Leap/SLE 15.0/1 (bsc#1173805).

Updated to 20.02.3 which fixes CVE-2020-12693 (bsc#1172004).

slurm-plugins will now also require pmix not only libpmix
(bsc#1164326)

Removed autopatch as it doesn't work for the SLE-11-SP4 build.

Disable %arm builds as this is no longer supported.

pmix searches now also for libpmix.so.2 so that there is no dependency
for devel package (bsc#1164386)

Update to version 20.02.0 (jsc#SLE-8491)

  - Fix minor memory leak in slurmd on reconfig.

  - Fix invalid ptr reference when rolling up data in the
    database.

  - Change shtml2html.py to require python3 for RHEL8
    support, and match man2html.py.

  - slurm.spec - override 'hardening' linker flags to ensure
    RHEL8 builds in a usable manner.

  - Fix type mismatches in the perl API.

  - Prevent use of uninitialized slurmctld_diag_stats.

  - Fixed various Coverity issues.

  - Only show warning about root-less topology in daemons.

  - Fix accounting of jobs in IGNORE_JOBS reservations.

  - Fix issue with batch steps state not loading correctly
    when upgrading from 19.05.

  - Deprecate max_depend_depth in SchedulerParameters and
    move it to DependencyParameters.

  - Silence erroneous error on slurmctld upgrade when
    loading federation state.

  - Break infinite loop in cons_tres dealing with incorrect
    tasks per tres request resulting in slurmctld hang.

  - Improve handling of --gpus-per-task to make sure
    appropriate number of GPUs is assigned to job.

  - Fix seg fault on cons_res when requesting --spread-job.

Move to python3 for everything but SLE-11-SP4

  - For SLE-11-SP4 add a workaround to handle a python3
    script (python2.7 compliant).

  - sbatch - fix segfault when no newline at the end of a
    burst buffer file.

  - Change scancel to only check job's base state when
    matching -t options.

  - Save job dependency list in state files.

  - cons_tres - allow jobs to be run on systems with
    root-less topologies.

  - Restore pre-20.02pre1 PrologSlurmctld synchonization
    behavior to avoid various race conditions, and ensure
    proper batch job launch.

  - Add new slurmrestd command/daemon which implements the
    Slurm REST API.

standard slurm.conf uses now also SlurmctldHost on all build targets
(bsc#1162377)

start slurmdbd after mariadb (bsc#1161716)

Update to version 19.05.5 (jsc#SLE-8491)

  - Includes security fixes CVE-2019-19727, CVE-2019-19728,
    CVE-2019-12838.

  - Disable i586 builds as this is no longer supported.

  - Create libnss_slurm package to support user and group
    resolution thru slurmstepd.

Update to v18.08.9 for fixing CVE-2019-19728 (bsc#1159692).

  - Make Slurm compile on linux after sys/sysctl.h was
    deprecated.

  - Install slurmdbd.conf.example with 0600 permissions to
    encourage secure use. CVE-2019-19727.

  - srun - do not continue with job launch if --uid fails.
    CVE-2019-19728.

added pmix support jsc#SLE-10800

Use --with-shared-libslurm to build slurm binaries using libslurm.

Make libslurm depend on slurm-config.

Fix ownership of /var/spool/slurm on new installations and upgrade
(bsc#1158696).

Fix permissions of slurmdbd.conf (bsc#1155784, CVE-2019-19727).

Fix %posttrans macro _res_update to cope with added newline
(bsc#1153259).

Add package slurm-webdoc which sets up a web server to provide the
documentation for the version shipped.

Move srun from 'slurm' to 'slurm-node': srun is required on the nodes
as well so sbatch will work. 'slurm-node' is a requirement when
'slurm' is installed (bsc#1153095).

Updated to 18.08.8 for fixing (CVE-2019-12838, bsc#1140709,
jsc#SLE-7341, jsc#SLE-7342)

  - Update 'xauth list' to use the same 10000ms timeout as
    the other xauth commands.

  - Fix issue in gres code to handle a gres cnt of 0.

  - Don't purge jobs if backfill is running.

  - Verify job is pending add/removing accrual time.

  - Don't abort when the job doesn't have an association
    that was removed before the job was able to make it to
    the database.

  - Set state_reason if select_nodes() fails job for QOS or
    Account.

  - Avoid seg_fault on referencing association without a
    valid_qos bitmap.

  - If Association/QOS is removed on a pending job set that
    job as ineligible.

  - When changing a jobs account/qos always make sure you
    remove the old limits.

  - Don't reset a FAIL_QOS or FAIL_ACCOUNT job reason until
    the qos or account changed.

  - Restore 'sreport -T ALL' functionality.

  - Correctly typecast signals being sent through the api.

  - Properly initialize structures throughout Slurm.

  - Sync 'numtask' squeue format option for jobs and steps
    to 'numtasks'.

  - Fix sacct -PD to avoid CA before start jobs.

  - Fix potential deadlock with backup slurmctld.

  - Fixed issue with jobs not appearing in sacct after
    dependency satisfied.

  - Fix showing non-eligible jobs when asking with -j and
    not -s.

  - Fix issue with backfill scheduler scheduling tasks of an
    array when not the head job.

  - accounting_storage/mysql - fix SIGABRT in the archive
    load logic.

  - accounting_storage/mysql - fix memory leak in the
    archive load logic.

  - Limit records per single SQL statement when loading
    archived data.

  - Fix unnecessary reloading of job submit plugins.

  - Allow job submit plugins to be turned on/off with a
    reconfigure.

  - Fix segfault when loading/unloading Lua job submit
    plugin multiple times.

  - Fix printing duplicate error messages of jobs rejected
    by job submit plugin.

  - Fix printing of job submit plugin messages of het jobs
    without pack id.

  - Fix memory leak in group_cache.c

  - Fix jobs stuck from FedJobLock when requeueing in a
    federation

  - Fix requeueing job in a federation of clusters with
    differing associations

  - sacctmgr - free memory before exiting in 'sacctmgr show
    runaway'.

  - Fix seff showing memory overflow when steps tres mem
    usage is 0.

  - Upon archive file name collision, create new archive
    file instead of overwriting the old one to prevent lost
    records.

  - Limit archive files to 50000 records per file so that
    archiving large databases will succeed.

  - Remove stray newlines in SPANK plugin error messages.

  - Fix archive loading events.

  - In select/cons_res: Only allocate 1 CPU per node with
    the --overcommit and --nodelist options.

  - Fix main scheduler from potentially not running through
    whole queue.

  - cons_res/job_test - prevent a job from overallocating a
    node memory.

  - cons_res/job_test - fix to consider a node's current
    allocated memory when testing a job's memory request.

  - Fix issue where multi-node job steps on cloud nodes
    wouldn't finish cleaning up until the end of the job
    (rather than the end of the step).

  - Fix issue with a 17.11 sbcast call to a 18.08 daemon.

  - Add new job bit_flags of JOB_DEPENDENT.

  - Make it so dependent jobs reset the AccrueTime and do
    not count against any AccrueTime limits.

  - Fix sacctmgr --parsable2 output for reservations and
    tres.

  - Prevent slurmctld from potential segfault after
    job_start_data() called for completing job.

  - Fix jobs getting on nodes with 'scontrol reboot asap'.

  - Record node reboot events to database.

  - Fix node reboot failure message getting to event table.

  - Don't write '(null)' to event table when no event reason
    exists.

  - Fix minor memory leak when clearing runaway jobs.

  - Avoid flooding slurmctld and logging when prolog
    complete RPC errors occur.

  - Fix GCC 9 compiler warnings.

  - Fix seff human readable memory string for values below a
    megabyte.

  - Fix dump/load of rejected heterogeneous jobs.

  - For heterogeneous jobs, do not count the each component
    against the QOS or association job limit multiple times.

  - slurmdbd - avoid reservation flag column corruption with
    the use of newer flags, instead preserve the older flag
    fields that we can still fit in the smallint field, and
    discard the rest.

  - Fix security issue in accounting_storage/mysql plugin on
    archive file loads by always escaping strings within the
    slurmdbd. CVE-2019-12838.

  - Fix underflow causing decay thread to exit.

  - Fix main scheduler not considering hetjobs when building
    the job queue.

  - Fix regression for sacct to display old jobs without a
    start time.

  - Fix setting correct number of gres topology bits.

  - Update hetjobs pending state reason when appropriate.

  - Fix accounting_storage/filetxt's understanding of TRES.

  - Set Accrue time when not enforcing limits.

  - Fix srun segfault when requesting a hetjob with
    test_exec or bcast options.

  - Hide multipart priorities log message behind Priority
    debug flag.

  - sched/backfill - Make hetjobs sensitive to
    bf_max_job_start.

  - Fix slurmctld segfault due to job's partition pointer
    NULL dereference.

  - Fix issue with OR'ed job dependencies.

  - Add new job's bit_flags of INVALID_DEPEND to prevent
    rebuilding a job's dependency string when it has at
    least one invalid and purged dependency.

  - Promote federation unsynced siblings log message from
    debug to info.

  - burst_buffer/cray - fix slurmctld SIGABRT due to illegal
    read/writes.

  - burst_buffer/cray - fix memory leak due to unfreed job
    script content.

  - node_features/knl_cray - fix script_argv use-after-free.

  - burst_buffer/cray - fix script_argv use-after-free.

  - Fix invalid reads of size 1 due to non null-terminated
    string reads.

  - Add extra debug2 logs to identify why BadConstraints
    reason is set.

Do not build hdf5 support where not available.

Add support for version updates on SLE: Update packages to a later
version than the version supported originally on SLE will receive a
version string in their package name.

added the hdf5 job data gathering plugin

Add backward compatibility with SLE-11 SP4

Update to version 18.08.05 :

  - Add mitigation for a potential heap overflow on 32-bit
    systems in xmalloc. (CVE-2019-6438, bsc#1123304)

Fix fallout from 750cc23ed for CVE-2019-6438.

Update to 18.08.04, with following highlights

  - Fix message sent to user to display preempted instead of
    time limit when a job is preempted.

  - Fix memory leak when a failure happens processing a
    nodes gres config.

  - Improve error message when failures happen processing a
    nodes gres config.

  - Don't skip jobs in scontrol hold.

  - Allow --cpu-bind=verbose to be used with SLURM_HINT
    environment variable.

  - Enhanced handling for runaway jobs

  - cons_res: Delay exiting cr_job_test until after
    cores/cpus are calculated and distributed.

  - Don't check existence of srun --prolog or --epilog
    executables when set to 'none' and SLURM_TEST_EXEC is
    used.

  - Add 'P' suffix support to job and step tres
    specifications.

  - Fix jobacct_gather/cgroup to work correctly when more
    than one task is started on a node.

  - salloc - set SLURM_NTASKS_PER_CORE and
    SLURM_NTASKS_PER_SOCKET in the environment if the
    corresponding command line options are used.

  - slurmd - fix handling of the -f flag to specify
    alternate config file locations.

  - Add SchedulerParameters option of
    bf_ignore_newly_avail_nodes to avoid scheduling lower
    priority jobs on resources that become available during
    the backfill scheduling cycle when bf_continue is
    enabled.

  - job_submit/lua: Add several slurmctld return codes and
    add user/group info

  - salloc/sbatch/srun - print warning if mutually exclusive
    options of

    --mem and --mem-per-cpu are both set.

restarting services on update only when activated

added rotation of logs

Added backported patches which harden the pam module pam_slurm_adopt.
(BOO#1116758)

Moved config man pages to a separate package: This way, they won't get
installed on compute nodes.

added correct link flags for perl bindings (bsc#1108671)

  - perl:Switch is required by slurm torque wrappers

Fix Requires(pre) and Requires(post) for slurm-config and slurm-node.
This fixes issues with failing slurm user creation when installed
during initial system installation. (bsc#1109373)

When using a remote shared StateSaveLocation, slurmctld needs to be
started after remote filesystems have become available. Add
'remote-fs.target' to the 'After=' directive in slurmctld.service
(bsc#1103561).

Update to 17.11.8

  - Fix incomplete RESPONSE_[RESOURCE|JOB_PACK]_ALLOCATION
    building path.

  - Do not allocate nodes that were marked down due to the
    node not responding by ResumeTimeout.

  - task/cray plugin - search for 'mems' cgroup information
    in the file 'cpuset.mems' then fall back to the file
    'mems'.

  - Fix ipmi profile debug uninitialized variable.

  - PMIx: fixed the direct connect inline msg sending.

  - MYSQL: Fix issue not handling all fields when loading an
    archive dump.

  - Allow a job_submit plugin to change the admin_comment
    field during job_submit_plugin_modify().

  - job_submit/lua - fix access into reservation table.

  - MySQL - Prevent deadlock caused by archive logic locking
    reads.

  - Don't enforce MaxQueryTimeRange when requesting specific
    jobs.

  - Modify --test-only logic to properly support jobs
    submitted to more than one partition.

  - Prevent slurmctld from abort when attempting to set
    non-existing qos as def_qos_id.

  - Add new job dependency type of 'afterburstbuffer'. The
    pending job will be delayed until the first job
    completes execution and it's burst buffer stage-out is
    completed.

  - Reorder proctrack/task plugin load in the slurmstepd to
    match that of slurmd and avoid race condition calling
    task before proctrack can introduce.

  - Prevent reboot of a busy KNL node when requesting
    inactive features.

  - Revert to previous behavior when requesting memory per
    cpu/node introduced in 17.11.7.

  - Fix to reinitialize previously adjusted job members to
    their original value when validating the job memory in
    multi-partition requests.

  - Fix _step_signal() from always returning SLURM_SUCCESS.

  - Combine active and available node feature change logs on
    one line rather than one line per node for performance
    reasons.

  - Prevent occasionally leaking freezer cgroups.

  - Fix potential segfault when closing the mpi/pmi2 plugin.

  - Fix issues with --exclusive=[user|mcs] to work correctly
    with preemption or when job requests a specific list of
    hosts.

  - Make code compile with hdf5 1.10.2+

  - mpi/pmix: Fixed the collectives canceling.

  - SlurmDBD: improve error message handling on archive load
    failure.

  - Fix incorrect locking when deleting reservations.

  - Fix incorrect locking when setting up the power save
    module.

  - Fix setting format output length for squeue when showing
    array jobs.

  - Add xstrstr function.

  - Fix printing out of --hint options in sbatch, salloc
    --help.

  - Prevent possible divide by zero in
    _validate_time_limit().

  - Add Delegate=yes to the slurmd.service file to prevent
    systemd from interfering with the jobs' cgroup
    hierarchies.

  - Change the backlog argument to the listen() syscall
    within srun to 4096 to match elsewhere in the code, and
    avoid communication problems at scale.

    Fix race in the slurmctld backup controller which
    prevents it to clean up allocations on nodes properly
    after failing over (bsc#1084917). Handled %license in a
    backward compatible manner.

Add a 'Recommends: slurm-munge' to slurm-slurmdbd.

Shield comments between script snippets with a %{!?nil:...} to avoid
them being interpreted as scripts - in which case the update level is
passed as argument (see chapter 'Shared libraries' in:
https://en.opensuse.org/openSUSE:Packaging_scriptlet_snippets)
(bsc#1100850).

Update from 17.11.5 to 17.11.7

Fix security issue in handling of username and gid fields
CVE-2018-10995 and bsc#1095508 what implied an update from 17.11.5 to
17.11.7 Highlights of 17.11.6 :

  - CRAY - Add slurmsmwd to the contribs/cray dir

  - PMIX - Added the direct connect authentication.

  - Prevent the backup slurmctld from losing the
    active/available node features list on takeover.

  - Be able to force power_down of cloud node even if in
    power_save state.

  - Allow cloud nodes to be recognized in Slurm when booted
    out of band.

  - Numerous fixes - check 'NEWS' file. Highlights of
    17.11.7 :

  - Notify srun and ctld when unkillable stepd exits.

  - Numerous fixes - check 'NEWS' file.

  - Fixes daemoniziation in newly introduced slurmsmwd
    daemon.

Rename :

  - remain in sync with commit messages which introduced
    that file

Avoid running pretrans scripts when running in an instsys: there may
be not much installed, yet. pretrans code should be done in lua, this
way, it will be executed by the rpm-internal lua interpreter and not
be passed to a shell which may not be around at the time this
scriptlet is run (bsc#1090292).

Add requires for slurm-sql to the slurmdbd package.

Package READMEs for pam and pam_slurm_adopt.

Use the new %%license directive for COPYING file. Fix interaction with
systemd: systemd expects that a daemonizing process doesn't go away
until the PID file with it PID of the daemon has bee written
(bsc#1084125).

Make sure systemd services get restarted only when all packages are in
a consistent state, not in the middle of an 'update' transaction
(bsc#1088693). Since the %postun scripts that run on update are from
the old package they cannot be changed - thus we work around the
restart breakage.

fixed wrong log file location in slurmdbd.conf and fixed pid location
for slurmdbd and made slurm-slurmdbd depend on slurm config which
provides the dir /var/run/slurm (bsc#1086859).

added comment for (bsc#1085606)

Fix security issue in accounting_storage/mysql plugin by always
escaping strings within the slurmdbd. CVE-2018-7033 (bsc#1085240).

Update slurm to v17.11.5 (FATE#325451) Highlights of 17.11 :

  - Support for federated clusters to manage a single
    work-flow across a set of clusters.

  - Support for heterogeneous job allocations (various
    processor types, memory sizes, etc. by job component).
    Support for heterogeneous job steps within a single
    MPI_COMM_WORLD is not yet supported for most
    configurations.

  - X11 support is now fully integrated with the main Slurm
    code. Remove any X11 plugin configured in your
    plugstack.conf file to avoid errors being logged about
    conflicting options.

  - Added new advanced reservation flag of 'flex', which
    permits jobs requesting the reservation to begin prior
    to the reservation's start time and use resources inside
    or outside of the reservation. A typical use case is to
    prevent jobs not explicitly requesting the reservation
    from using those reserved resources rather than forcing
    jobs requesting the reservation to use those resources
    in the time frame reserved.

  - The sprio command has been modified to report a job's
    priority information for every partition the job has
    been submitted to.

  - Group ID lookup performed at job submit time to avoid
    lookup on all compute nodes. Enable with
    PrologFlags=SendGIDs configuration parameter.

  - Slurm commands and daemons dynamically link to
    libslurmfull.so instead of statically linking. This
    dramatically reduces the footprint of Slurm.

  - In switch plugin, added plugin_id symbol to plugins and
    wrapped switch_jobinfo_t with dynamic_plugin_data_t in
    interface calls in order to pass switch information
    between clusters with different switch types.

  - Changed default ProctrackType to cgroup.

  - Changed default sched_min_interval from 0 to 2
    microseconds.

  - Added new 'scontrol write batch_script ' command to
    fetch a job's batch script. Removed the ability to see
    the script as part of the 'scontrol -dd show job'
    command.

  - Add new 'billing' TRES which allows jobs to be limited
    based on the job's billable TRES calculated by the job's
    partition's TRESBillingWeights.

  - Regular user use of 'scontrol top' command is now
    disabled. Use the configuration parameter
    'SchedulerParameters=enable_user_top' to enable that
    functionality. The configuration parameter
    'SchedulerParameters=disable_user_top' will be silently
    ignored.

  - Change default to let pending jobs run outside of
    reservation after reservation is gone to put jobs in
    held state. Added NO_HOLD_JOBS_AFTER_END reservation
    flag to use old default. Support for PMIx v2.0 as well
    as UCX support.

  - Remove plugins for obsolete MPI stacks :

  - lam

  - mpich1_p4

  - mpich1_shmem

  - mvapich

  - Numerous fixes - check 'NEWS' file. Replaced by sed
    script.

Fix some rpmlint warnings.

moved config files to slurm-config package (FATE#324574).

Moved slurmstepd and man page into slurm-node due to slurmd dependency

Moved config files into slurm-node

Moved slurmd rc scripts into slurm-node

Made slurm-munge require slurm-plugins instead of slurm itself

  - slurm-node suggested slurm-munge, causing the whole
    slurm to be installed. The slurm-plugins seems to be a
    more base class (FATE#324574).

split up light wight slurm-node package for deployment on nodes
(FATE#324574).

Package so-versioned libs separately. libslurm is expected to change
more frequently and thus is packaged separately from libpmi.

Updated to 17.02.9 to fix CVE-2017-15566 (bsc#1065697). Changes in
17.0.9

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
    of it's child process.

  - Fix security issue in Prolog and Epilog by always
    prepending SPANK_ to all user-set environment variables.
    CVE-2017-15566. Changes in 17.0.8 :

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
    field with a type set correctly.

Fixed ABI version of libslurm.

Trim redundant wording in descriptions.

Updated to slurm 17-02-7-1

  - Added python as BuildRequires

  - Removed sched-wiki package

  - Removed slurmdb-direct package

  - Obsoleted sched-wiki and slurmdb-direct packages

  - Removing Cray-specific files

  - Added /etc/slurm/layout.d files (new for this version)

  - Remove /etc/slurm/cgroup files from package

  - Added lib/slurm/mcs_account.so

  - Removed lib/slurm/jobacct_gather_aix.so

  - Removed lib/slurm/job_submit_cnode.so

Created slurm-sql package

Moved files from slurm-plugins to slurm-torque package

Moved creation of /usr/lib/tmpfiles.d/slurm.conf into slurm.spec

  - Removed tmpfiles.d-slurm.conf

Changed /var/run path for slurm daemons to /var/run/slurm
(FATE#324026).

Made tmpfiles_create post-install macro SLE12 SP2 or greater

Directly calling systemd-tmpfiles --create for before SLE12 SP2

Allows OpenSUSE Factory build as well

Removes unused .service files from project

Adds /var/run/slurm to /usr/lib/tmpfiles.d for boottime creation

  - Patches upstream .service files to allow for
    /var/run/slurm path

  - Modifies slurm.conf to allow for /var/run/slurm path

Move wrapper script mpiexec provided by slrum-torque to mpiexec.slurm
to avoid conflicts. This file is normally provided by the MPI
implementation (bsc#1041706).

Replace remaining ${RPM_BUILD_ROOT}s.

Improve description.

Fix up changelog.

Spec file: Replace 'Requires : slurm-perlapi' by 'Requires: perl-slurm
= %{version}' (bsc#1031872).

Trim redundant parts of description. Fixup RPM groups.

Replace unnecessary %__ macro indirections; replace historic $RPM_*
variables by macros.

Use %slurm_u and %slurm_g macros defined at the beginning of the spec
file when adding the slurm user/group for consistency.

Define these macros to daemon,root for non-systemd.

For anything newer than Leap 42.1 or SLE-12-SP1 build OpenHPC
compatible.

Updated to 16.05.8.1

  - Remove StoragePass from being printed out in the
    slurmdbd log at debug2 level.

  - Defer PATH search for task program until launch in
    slurmstepd.

  - Modify regression test1.89 to avoid leaving vestigial
    job. Also reduce logging to reduce likelyhood of Expect
    buffer overflow.

  - Do not PATH search for mult-prog launches if
    LaunchParamters=test_exec is enabled.

  - Fix for possible infinite loop in select/cons_res plugin
    when trying to satisfy a job's ntasks_per_core or socket
    specification.

  - If job is held for bad constraints make it so once
    updated the job doesn't go into JobAdminHeld.

  - sched/backfill - Fix logic to reserve resources for jobs
    that require a node reboot (i.e. to change KNL mode) in
    order to start.

  - When unpacking a node or front_end record from state and
    the protocol version is lower than the min version, set
    it to the min.

  - Remove redundant lookup for part_ptr when updating a
    reservation's nodes.

  - Fix memory and file descriptor leaks in slurmd daemon's
    sbcast logic.

  - Do not allocate specialized cores to jobs using the
    --exclusive option.

  - Cancel interactive job if Prolog failure with
    'PrologFlags=contain' or 'PrologFlags=alloc' configured.
    Send new error prolog failure message to the salloc or
    srun command as needed.

  - Prevent possible out-of-bounds read in slurmstepd on an
    invalid #! line.

  - Fix check for PluginDir within slurmctld to work with
    multiple directories.

  - Cancel interactive jobs automatically on communication
    error to launching srun/salloc process.

  - Fix security issue caused by insecure file path handling
    triggered by the failure of a Prolog script. To exploit
    this a user needs to anticipate or cause the Prolog to
    fail for their job. CVE-2016-10030 (bsc#1018371).

Replace group/user add macros with function calls.

Fix array initialzation and ensure strings are always NULL terminated
in

pam_slurm.c (bsc#1007053).

Disable building with netloc support: the netloc API is part of the
devel branch of hwloc. Since this devel branch was included
accidentally and has been reversed since, we need to disable this for
the time being.

Conditionalized architecture specific pieces to support non-x86
architectures better.

Remove: unneeded 'BuildRequires: python'

Add: BuildRequires: freeipmi-devel BuildRequires: libibmad-devel
BuildRequires: libibumad-devel so they are picked up by the slurm
build.

Enable modifications from openHPC Project.

Enable lua API package build.

Add a recommends for slurm-munge to the slurm package: This is way,
the munge auth method is available and slurm works out of the box.

Create /var/lib/slurm as StateSaveLocation directory. /tmp is
dangerous.

Create slurm user/group in preinstall script.

Keep %{_libdir}/libpmi* and %{_libdir}/mpi_pmi2* on SUSE.

Fix build with and without OHCP_BUILD define.

Fix build for systemd and non-systemd.

Updated to 16-05-5 - equvalent to OpenHPC 1.2.

  - Fix issue with resizing jobs and limits not be kept
    track of correctly.

  - BGQ - Remove redeclaration of job_read_lock.

  - BGQ - Tighter locks around structures when nodes/cables
    change state.

  - Make it possible to change CPUsPerTask with scontrol.

  - Make it so scontrol update part qos= will take away a
    partition QOS from a partition.

  - Backfill scheduling properly synchronized with Cray Node
    Health Check. Prior logic could result in highest
    priority job getting improperly postponed.

  - Make it so daemons also support
    TopologyParam=NoInAddrAny.

  - If scancel is operating on large number of jobs and RPC
    responses from slurmctld daemon are slow then introduce
    a delay in sending the cancel job requests from scancel
    in order to reduce load on slurmctld.

  - Remove redundant logic when updating a job's task count.

  - MySQL - Fix querying jobs with reservations when the
    id's have rolled.

  - Perl - Fix use of uninitialized variable in
    slurm_job_step_get_pids.

  - Launch batch job requsting --reboot after the boot
    completes.

  - Do not attempt to power down a node which has never
    responded if the slurmctld daemon restarts without
    state.

  - Fix for possible slurmstepd segfault on invalid user ID.

  - MySQL - Fix for possible race condition when archiving
    multiple clusters at the same time.

  - Add logic so that slurmstepd can be launched under
    valgrind.

  - Increase buffer size to read /proc/*/stat files.

  - Remove the SchedulerParameters option of
    'assoc_limit_continue', making it the default value. Add
    option of 'assoc_limit_stop'. If 'assoc_limit_stop' is
    set and a job cannot start due to association limits,
    then do not attempt to initiate any lower priority jobs
    in that partition. Setting this can decrease system
    throughput and utlization, but avoid potentially
    starving larger jobs by preventing them from launching
    indefinitely.

  - Update a node's socket and cores per socket counts as
    needed after a node boot to reflect configuration
    changes which can occur on KNL processors. Note that the
    node's total core count must not change, only the
    distribution of cores across varying socket counts (KNL
    NUMA nodes treated as sockets by Slurm).

  - Rename partition configuration from 'Shared' to
    'OverSubscribe'. Rename salloc, sbatch, srun option from
    '--shared' to '--oversubscribe'. The old options will
    continue to function. Output field names also changed in
    scontrol, sinfo, squeue and sview.

  - Add SLURM_UMASK environment variable to user job.

  - knl_conf: Added new configuration parameter of
    CapmcPollFreq.

  - Cleanup two minor Coverity warnings.

  - Make it so the tres units in a job's formatted string
    are converted like they are in a step.

  - Correct partition's MaxCPUsPerNode enforcement when
    nodes are shared by multiple partitions.

  - node_feature/knl_cray - Prevent slurmctld GRES errors
    for 'hbm' references.

  - Display thread name instead of thread id and remove
    process name in stderr logging for 'thread_id'
    LogTimeFormat.

  - Log IP address of bad incomming message to slurmctld.

  - If a user requests tasks, nodes and ntasks-per-node and
    tasks-per-node/nodes != tasks print warning and ignore
    ntasks-per-node.

  - Release CPU 'owner' file locks.

  - Update seff to fix warnings with ncpus, and list
    slurm-perlapi dependency in spec file.

  - Allow QOS timelimit to override partition timelimit when
    EnforcePartLimits is set to all/any.

  - Make it so qsub will do a 'basename' on a wrapped
    command for the output and error files.

  - Add logic so that slurmstepd can be launched under
    valgrind.

  - Increase buffer size to read /proc/*/stat files.

  - Prevent job stuck in configuring state if slurmctld
    daemon restarted while PrologSlurmctld is running. Also
    re-issue burst_buffer/pre-load operation as needed.

  - Move test for job wait reason value of
    BurstBufferResources and BurstBufferStageIn later in the
    scheduling logic.

  - Document which srun options apply to only job, only
    step, or job and step allocations.

  - Use more compatible function to get thread name (>=
    2.6.11).

  - Make it so the extern step uses a reverse tree when
    cleaning up.

  - If extern step doesn't get added into the proctrack
    plugin make sure the sleep is killed.

  - Add web links to Slurm Diamond Collectors (from Harvard
    University) and collectd (from EDF).

  - Add job_submit plugin for the 'reboot' field.

  - Make some more Slurm constants (INFINITE, NO_VAL64,
    etc.) available to job_submit/lua plugins.

  - Send in a -1 for a taskid into spank_task_post_fork for
    the extern_step.

  - MYSQL - Sightly better logic if a job completion comes
    in with an end time of 0.

  - task/cgroup plugin is configured with
    ConstrainRAMSpace=yes, then set soft memory limit to
    allocated memory limit (previously no soft limit was
    set).

  - Streamline when schedule() is called when running with
    message aggregation on batch script completes.

  - Fix incorrect casting when [un]packing derived_ec on
    slurmdb_job_rec_t.

  - Document that persistent burst buffers can not be
    created or destroyed using the salloc or srun --bb
    options.

  - Add support for setting the SLURM_JOB_ACCOUNT,
    SLURM_JOB_QOS and SLURM_JOB_RESERVAION environment
    variables are set for the salloc command. Document the
    same environment variables for the salloc, sbatch and
    srun commands in their man pages.

  - Fix issue where sacctmgr load cluster.cfg wouldn't load
    associations that had a partition in them.

  - Don't return the extern step from sstat by default.

  - In sstat print 'extern' instead of 4294967295 for the
    extern step.

  - Make advanced reservations work properly with core
    specialization.

  - slurmstepd modified to pre-load all relevant plugins at
    startup to avoid the possibility of modified plugins
    later resulting in inconsistent API or data structures
    and a failure of slurmstepd.

  - Export functions from parse_time.c in libslurm.so.

  - Export unit convert functions from slurm_protocol_api.c
    in libslurm.so.

  - Fix scancel to allow multiple steps from a job to be
    cancelled at once.

  - Update and expand upgrade guide (in Quick Start
    Administrator web page).

  - burst_buffer/cray: Requeue, but do not hold a job which
    fails the pre_run operation.

  - Insure reported expected job start time is not in the
    past for pending jobs.

  - Add support for PMIx v2. Required for FATE#316379.

Setting 'download_files' service to mode='localonly' and adding source
tarball. (Required for Factory).

version 15.08.7.1

  - Remove the 1024-character limit on lines in batch
    scripts. task/affinity: Disable core-level task binding
    if more CPUs required than available cores.

  - Preemption/gang scheduling: If a job is suspended at
    slurmctld restart or reconfiguration time, then leave it
    suspended rather than resume+suspend.

  - Don't use lower weight nodes for job allocation when
    topology/tree used.

  - Don't allow user specified reservation names to disrupt
    the normal reservation sequeuece numbering scheme.

  - Avoid hard-link/copy of script/environment files for job
    arrays. Use the master job record file for all tasks of
    the job array. NOTE: Job arrays submitted to Slurm
    version 15.08.6 or later will fail if the slurmctld
    daemon is downgraded to an earlier version of Slurm.

  - In slurmctld log file, log duplicate job ID found by
    slurmd. Previously was being logged as prolog/epilog
    failure.

  - If a job is requeued while in the process of being
    launch, remove it's job ID from slurmd's record of
    active jobs in order to avoid generating a duplicate job
    ID error when launched for the second time (which would
    drain the node).

  - Cleanup messages when handling job script and
    environment variables in older directory structure
    formats.

  - Prevent triggering gang scheduling within a partition if
    configured with PreemptType=partition_prio and
    PreemptMode=suspend,gang.

  - Decrease parallelism in job cancel request to prevent
    denial of service when cancelling huge numbers of jobs.

  - If all ephemeral ports are in use, try using other port
    numbers.

  - Prevent 'scontrol update job' from updating jobs that
    have already finished.

  - Show requested TRES in 'squeue -O tres' when job is
    pending.

  - Backfill scheduler: Test association and QOS node limits
    before reserving resources for pending job.

  - Many bug fixes.

Use source services to download package.

Fix code for new API of hwloc-2.0.

package netloc_to_topology where avialable.

Package documentation.

version 15.08.3

  - Many new features and bug fixes. See NEWS file

update files list accordingly

fix wrong end of line in some files

version 14.11.8

  - Many bug fixes. See NEWS file

update files list accordingly

add missing systemd requirements

add missing rclink

version 14.03.9

  - Many bug fixes. See NEWS file

add systemd support

version 14.03.6

  - Added support for native Slurm operation on Cray systems
    (without ALPS).

  - Added partition configuration parameters AllowAccounts,
    AllowQOS, DenyAccounts and DenyQOS to provide greater
    control over use.

  - Added the ability to perform load based scheduling.
    Allocating resources to jobs on the nodes with the
    largest number if idle CPUs.

  - Added support for reserving cores on a compute node for
    system services (core specialization)

  - Add mechanism for job_submit plugin to generate error
    message for srun, salloc or sbatch to stderr.

  - Support for Postgres database has long since been out of
    date and problematic, so it has been removed entirely.
    If you would like to use it the code still exists in <=
    2.6, but will not be included in this and future
    versions of the code.

  - Added new structures and support for both server and
    cluster resources.

  - Significant performance improvements, especially with
    respect to job array support.

update files list

update to version 2.6.7

  - Support for job arrays, which increases performance and
    ease of use for sets of similar jobs.

  - Job profiling capability added to record a wide variety
    of job characteristics for each task on a user
    configurable periodic basis. Data currently available
    includes CPU use, memory use, energy use, Infiniband
    network use, Lustre file system use, etc.

  - Support for MPICH2 using PMI2 communications interface
    with much greater scalability.

  - Prolog and epilog support for advanced reservations.

  - Much faster throughput for job step execution with
    --exclusive option. The srun process is notified when
    resources become available rather than periodic polling.

  - Support improved for Intel MIC (Many Integrated Core)
    processor.

  - Advanced reservations with hostname and core counts now
    supports asymmetric reservations (e.g. specific
    different core count for each node).

  - External sensor plugin infrastructure added to record
    power consumption, temperature, etc.

  - Improved performance for high-throughput computing.

  - MapReduce+ support (launches ~1000x faster, runs ~10x
    faster).

  - Added 'MaxCPUsPerNode' partition configuration
    parameter. This can be especially useful to schedule
    GPUs. For example a node can be associated with two
    Slurm partitions (e.g. 'cpu' and 'gpu') and the
    partition/queue 'cpu' could be limited to only a subset
    of the node's CPUs, insuring that one or more CPUs would
    be available to jobs in the 'gpu' partition/queue.

version 2.5.7

  - Fix for linking to the select/cray plugin to not give
    warning about undefined variable.

  - Add missing symbols to the xlator.h

  - Avoid placing pending jobs in AdminHold state due to
    backfill scheduler interactions with advanced
    reservation.

  - Accounting - make average by task not cpu.

  - POE - Correct logic to support poe option '-euidevice
    sn_all' and '-euidevice sn_single'.

  - Accounting - Fix minor initialization error.

  - POE - Correct logic to support srun network instances
    count with POE.

  - POE - With the srun --launch-cmd option, report proper
    task count when the --cpus-per-task option is used
    without the

    --ntasks option.

  - POE - Fix logic binding tasks to CPUs.

  - sview - Fix race condition where new information could
    of slipped past the node tab and we didn't notice.

  - Accounting - Fix an invalid memory read when slurmctld
    sends data about start job to slurmdbd.

  - If a prolog or epilog failure occurs, drain the node
    rather than setting it down and killing all of its jobs.

  - Priority/multifactor - Avoid underflow in half-life
    calculation.

  - POE - pack missing variable to allow fanout (more than
    32 nodes)

  - Prevent clearing reason field for pending jobs. This bug
    was introduced in v2.5.5 (see 'Reject job at submit time
    ...').

  - BGQ - Fix issue with preemption on sub-block jobs where
    a job would kill all preemptable jobs on the midplane
    instead of just the ones it needed to.

  - switch/nrt - Validate dynamic window allocation size.

  - BGQ - When --geo is requested do not impose the default
    conn_types.

  - RebootNode logic - Defers (rather than forgets) reboot
    request with job running on the node within a
    reservation.

  - switch/nrt - Correct network_id use logic. Correct
    support for user sn_all and sn_single options.

  - sched/backfill - Modify logic to reduce overhead under
    heavy load.

  - Fix job step allocation with --exclusive and --hostlist
    option.

  - Select/cons_res - Fix bug resulting in error of
    'cons_res: sync loop not progressing, holding job #'

  - checkpoint/blcr - Reset max_nodes from zero to NO_VAL on
    job restart.

  - launch/poe - Fix for hostlist file support with repeated
    host names.

  - priority/multifactor2 - Prevent possible divide by zero.

    -- srun - Don't check for executable if --test-only flag
    is used.

  - energy - On a single node only use the last task for
    gathering energy. Since we don't currently track energy
    usage per task (only per step). Otherwise we get double
    the energy.

version 2.5.4

  - Support for Intel&Acirc;&reg; Many Integrated Core (MIC)
    processors.

  - User control over CPU frequency of each job step.

  - Recording power usage information for each job.

  - Advanced reservation of cores rather than whole nodes.

  - Integration with IBM's Parallel Environment including
    POE (Parallel Operating Environment) and NRT (Network
    Resource Table) API.

  - Highly optimized throughput for serial jobs in a new
    'select/serial' plugin.

  - CPU load is information available

  - Configurable number of CPUs available to jobs in each
    SLURM partition, which provides a mechanism to reserve
    CPUs for use with GPUs.

remore runlevel 4 from init script thanks to patch1

fix self obsoletion of slurm-munge package

use fdupes to remove duplicates

spec file reformaing

put perl macro in a better within install section

enable numa on x86_64 arch only

add numa and hwloc support

fix perl module files list

use perl_process_packlist macro for the perl files cleanup

fix some summaries length

add cgoups directory and example the cgroup.release_common file

spec file cleanup

first package

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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178891");
  script_set_attribute(attribute:"see_also", value:"https://en.opensuse.org/openSUSE:Packaging_scriptlet_snippets");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-10030/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-15566/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10995/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-7033/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12838/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19727/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19728/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-6438/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12693/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27745/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27746/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210773-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18cd535c");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for HPC 12 :

zypper in -t patch SUSE-SLE-Module-HPC-12-2021-773=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10030");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-27745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnss_slurm2_20_11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnss_slurm2_20_11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0_20_11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0_20_11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm36-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-slurm_20_02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-slurm_20_02-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-slurm_20_11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh-slurm_20_11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh_slurm_18_08-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh_slurm_20_02-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pdsh_slurm_20_11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm_20_11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm_20_11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-auth-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-auth-none-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-config-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-munge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-munge-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-node-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-pam_slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-pam_slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-slurmdbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-sview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-sview-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-torque-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm_20_11-webdoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libnss_slurm2_20_11-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libnss_slurm2_20_11-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libpmi0_20_11-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libpmi0_20_11-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libslurm36-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libslurm36-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-debuginfo-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-debugsource-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-dshgroup-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-dshgroup-debuginfo-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-genders-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-genders-debuginfo-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-machines-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-machines-debuginfo-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-netgroup-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-netgroup-debuginfo-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-slurm-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-slurm-debuginfo-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-slurm_18_08-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-slurm_18_08-debuginfo-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-slurm_20_02-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-slurm_20_02-debuginfo-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-slurm_20_11-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh-slurm_20_11-debuginfo-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh_slurm_18_08-debugsource-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh_slurm_20_02-debugsource-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"pdsh_slurm_20_11-debugsource-2.34-7.32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"perl-slurm_20_11-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"perl-slurm_20_11-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-auth-none-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-auth-none-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-config-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-config-man-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-debugsource-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-devel-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-doc-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-lua-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-lua-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-munge-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-munge-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-node-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-node-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-pam_slurm-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-pam_slurm-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-plugins-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-plugins-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-slurmdbd-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-slurmdbd-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-sql-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-sql-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-sview-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-sview-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-torque-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-torque-debuginfo-20.11.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"slurm_20_11-webdoc-20.11.4-3.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "slurm_20_11 / pdsh");
}
