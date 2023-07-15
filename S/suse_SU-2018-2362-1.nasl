#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2362-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(111830);
  script_version("1.5");
  script_cvs_date("Date: 2019/09/10 13:51:48");

  script_cve_id("CVE-2018-13053", "CVE-2018-13405", "CVE-2018-13406", "CVE-2018-14734", "CVE-2018-3620", "CVE-2018-3646");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2018:2362-1) (Foreshadow)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 GA LTSS kernel was updated to receive
various security and bugfixes. The following security bugs were 
fixed :

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
    (bnc#1098016 bnc#1100418).

  - CVE-2018-14734: drivers/infiniband/core/ucma.c allowed
    ucma_leave_multicast to access a certain data structure
    after a cleanup step in ucma_process_join, which allowed
    attackers to cause a denial of service (use-after-free)
    (bnc#1103119).

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

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068032"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1098016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1099924"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103119"
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
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182362-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?251f7562"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-1605=1

SUSE Linux Enterprise Module for Public Cloud 12:zypper in -t patch
SUSE-SLE-Module-Public-Cloud-12-2018-1605=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_61-52_141-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_61-52_141-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.61-52.141.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.61-52.141.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.61-52.141.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.61-52.141.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.61-52.141.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.61-52.141.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kgraft-patch-3_12_61-52_141-default-1-1.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kgraft-patch-3_12_61-52_141-xen-1-1.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"lttng-modules-2.4.1-16.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"lttng-modules-debugsource-2.4.1-16.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"lttng-modules-kmp-default-2.4.1_k3.12.61_52.141-16.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"lttng-modules-kmp-default-debuginfo-2.4.1_k3.12.61_52.141-16.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.61-52.141.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.61-52.141.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.61-52.141.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.61-52.141.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.61-52.141.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.61-52.141.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.61-52.141.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.61-52.141.1")) flag++;


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
