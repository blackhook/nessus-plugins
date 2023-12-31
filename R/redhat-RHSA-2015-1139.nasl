#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1139. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84358);
  script_version("2.9");
  script_cvs_date("Date: 2019/10/24 15:35:40");

  script_cve_id("CVE-2014-9420", "CVE-2014-9529", "CVE-2014-9584", "CVE-2015-1573", "CVE-2015-1593", "CVE-2015-1805", "CVE-2015-2830");
  script_xref(name:"RHSA", value:"2015:1139");

  script_name(english:"RHEL 7 : kernel-rt (RHSA-2015:1139)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel-rt packages that fix multiple security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel-rt packages contain the Linux kernel, the core of any Linux
operating system.

* It was found that the Linux kernel's implementation of vectored pipe
read and write functionality did not take into account the I/O vectors
that were already processed when retrying after a failed atomic access
operation, potentially resulting in memory corruption due to an I/O
vector array overrun. A local, unprivileged user could use this flaw
to crash the system or, potentially, escalate their privileges on the
system. (CVE-2015-1805, Important)

* A race condition flaw was found in the way the Linux kernel keys
management subsystem performed key garbage collection. A local
attacker could attempt accessing a key while it was being garbage
collected, which would cause the system to crash. (CVE-2014-9529,
Moderate)

* A flaw was found in the way the Linux kernel's 32-bit emulation
implementation handled forking or closing of a task with an 'int80'
entry. A local user could potentially use this flaw to escalate their
privileges on the system. (CVE-2015-2830, Low)

* It was found that the Linux kernel's ISO file system implementation
did not correctly limit the traversal of Rock Ridge extension
Continuation Entries (CE). An attacker with physical access to the
system could use this flaw to trigger an infinite loop in the kernel,
resulting in a denial of service. (CVE-2014-9420, Low)

* An information leak flaw was found in the way the Linux kernel's
ISO9660 file system implementation accessed data on an ISO9660 image
with RockRidge Extension Reference (ER) records. An attacker with
physical access to the system could use this flaw to disclose up to
255 bytes of kernel memory. (CVE-2014-9584, Low)

* A flaw was found in the way the nft_flush_table() function of the
Linux kernel's netfilter tables implementation flushed rules that were
referencing deleted chains. A local user who has the CAP_NET_ADMIN
capability could use this flaw to crash the system. (CVE-2015-1573,
Low)

* An integer overflow flaw was found in the way the Linux kernel
randomized the stack for processes on certain 64-bit architecture
systems, such as x86-64, causing the stack entropy to be reduced by
four. (CVE-2015-1593, Low)

Red Hat would like to thank Carl Henrik Lunde for reporting
CVE-2014-9420 and CVE-2014-9584. The security impact of CVE-2015-1805
was discovered by Red Hat.

The kernel-rt packages have been upgraded to version 3.10.0-229.7.2,
which provides a number of bug fixes and enhancements over the
previous version, including :

* storvsc: get rid of overly verbose warning messages

* storvsc: force discovery of LUNs that may have been removed

* storvsc: in responce to a scan event, scan the hos

* storvsc: NULL pointer dereference fix

* futex: Mention key referencing differences between shared and
private futexes

* futex: Ensure get_futex_key_refs() always implies a barrier

* kernel module: set nx before marking module MODULE_STATE_COMING

* kernel module: Clean up ro/nx after early module load failures

* btrfs: make xattr replace operations atomic

* megaraid_sas: revert: Add release date and update driver version

* radeon: fix kernel segfault in hwmonitor

(BZ#1223955)

Bug fix :

* There is an XFS optimization that depended on a spinlock to disable
preemption using the preempt_disable() function. When
CONFIG_PREEMPT_RT is enabled on realtime kernels, spinlocks do not
disable preemption while held, so the XFS critical section was not
protected from preemption. Systems on the Realtime kernel-rt could
lock up in this XFS optimization when a task that locked all the
counters was then preempted by a realtime task, causing all callers of
that lock to block indefinitely. This update disables the optimization
when building a kernel with CONFIG_PREEMPT_RT_FULL enabled.
(BZ#1223955)

All kernel-rt users are advised to upgrade to these updated packages,
which correct these issues and add these enhancements. The system must
be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:1139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-9420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-9529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-9584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-1573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-1593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-1805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-2830"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");
include("ksplice.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2014-9420", "CVE-2014-9529", "CVE-2014-9584", "CVE-2015-1573", "CVE-2015-1593", "CVE-2015-1805", "CVE-2015-2830");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2015:1139");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1139";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-3.10.0-229.7.2.rt56.141.6.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-3.10.0-229.7.2.rt56.141.6.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-devel-3.10.0-229.7.2.rt56.141.6.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-devel-3.10.0-229.7.2.rt56.141.6.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", reference:"kernel-rt-doc-3.10.0-229.7.2.rt56.141.6.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-3.10.0-229.7.2.rt56.141.6.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-devel-3.10.0-229.7.2.rt56.141.6.el7_1")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt / kernel-rt-debug / kernel-rt-debug-devel / etc");
  }
}
