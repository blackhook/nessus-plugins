#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2344-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(111815);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/08");

  script_cve_id("CVE-2017-18344", "CVE-2018-13053", "CVE-2018-13405", "CVE-2018-13406", "CVE-2018-14734", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390", "CVE-2018-5391", "CVE-2018-5814", "CVE-2018-9385");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2018:2344-1) (Foreshadow)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The SUSE Linux Enterprise 12 SP2 LTSS kernel was updated to receive
various security and bugfixes. The following security bugs were 
fixed :

  - CVE-2018-3620: Local attackers on baremetal systems
    could use speculative code patterns on hyperthreaded
    processors to read data present in the L1 Datacache used
    by other hyperthreads on the same CPU core, potentially
    leaking sensitive data. (bnc#1087081).

  - CVE-2018-3646: Local attackers in virtualized guest
    systems could use speculative code patterns on
    hyperthreaded processors to read data present in the L1
    Datacache used by other hyperthreads on the same CPU
    core, potentially leaking sensitive data, even from
    other virtual machines or the host system.
    (bnc#1089343).

  - CVE-2018-5390 aka 'SegmentSmack': The Linux Kernel can
    be forced to make very expensive calls to
    tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() for
    every incoming packet which can lead to a denial of
    service (bnc#1102340).

  - CVE-2018-5391 aka 'FragmentSmack': A flaw in the IP
    packet reassembly could be used by remote attackers to
    consume lots of CPU time (bnc#1103097).

  - CVE-2018-14734: drivers/infiniband/core/ucma.c allowed
    ucma_leave_multicast to access a certain data structure
    after a cleanup step in ucma_process_join, which allowed
    attackers to cause a denial of service (use-after-free)
    (bnc#1103119).

  - CVE-2017-18344: The timer_create syscall implementation
    in kernel/time/posix-timers.c didn't properly validate
    the sigevent->sigev_notify field, which leads to
    out-of-bounds access in the show_timer function (called
    when /proc/$PID/timers is read). This allowed userspace
    applications to read arbitrary kernel memory (on a
    kernel built with CONFIG_POSIX_TIMERS and
    CONFIG_CHECKPOINT_RESTORE) (bnc#1102851 bnc#1103580).

  - CVE-2018-9385: When printing the 'driver_override'
    option from with-in the amba driver, a very long line
    could expose one additional uninitialized byte
    (bnc#1100491).

  - CVE-2018-13053: The alarm_timer_nsleep function in
    kernel/time/alarmtimer.c had an integer overflow via a
    large relative timeout because ktime_add_safe is not
    used (bnc#1099924).

  - CVE-2018-13405: The inode_init_owner function in
    fs/inode.c allowed local users to create files with an
    unintended group ownership, in a scenario where a
    directory is SGID to a certain group and is writable by
    a user who is not a member of that group. Here, the
    non-member can trigger creation of a plain file whose
    group ownership is that group. The intended behavior was
    that the non-member can trigger creation of a directory
    (but not a plain file) whose group ownership is that
    group. The non-member can escalate privileges by making
    the plain file executable and SGID (bnc#1100416).

  - CVE-2018-13406: An integer overflow in the
    uvesafb_setcmap function in
    drivers/video/fbdev/uvesafb.c could result in local
    attackers being able to crash the kernel or potentially
    elevate privileges because kmalloc_array is not used
    (bnc#1098016 1100418).

  - CVE-2018-5814: Multiple race condition errors when
    handling probe, disconnect, and rebind operations could
    be exploited to trigger a use-after-free condition or a
    NULL pointer dereference by sending multiple USB over IP
    packets (bnc#1096480).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1085042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1089343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1094248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1098016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1098425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1098435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1099924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1100089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1100416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1100418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1100491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1102340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1102851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18344/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-13053/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-13405/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-13406/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14734/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3620/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3646/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5390/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5391/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5814/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-9385/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182344-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b3ecdf9"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-1603=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-1603=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-1603=1

SUSE Linux Enterprise High Availability 12-SP2:zypper in -t patch
SUSE-SLE-HA-12-SP2-2018-1603=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-1603=1

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2018-1603=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_92-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_92-default-1-3.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"lttng-modules-2.7.1-9.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"lttng-modules-debugsource-2.7.1-9.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"lttng-modules-kmp-default-2.7.1_k4.4.121_92.92-9.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"lttng-modules-kmp-default-debuginfo-2.7.1_k4.4.121_92.92-9.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"s390x", reference:"kernel-default-man-4.4.121-92.92.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-default-4.4.121-92.92.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-default-base-4.4.121-92.92.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-default-base-debuginfo-4.4.121-92.92.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-default-debuginfo-4.4.121-92.92.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-default-debugsource-4.4.121-92.92.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-default-devel-4.4.121-92.92.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-syms-4.4.121-92.92.1")) flag++;


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
