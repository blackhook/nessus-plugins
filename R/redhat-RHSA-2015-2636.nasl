#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2636. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87398);
  script_version("2.15");
  script_cvs_date("Date: 2019/10/24 15:35:40");

  script_cve_id("CVE-2015-2925", "CVE-2015-5307", "CVE-2015-7613", "CVE-2015-7872", "CVE-2015-8104");
  script_xref(name:"RHSA", value:"2015:2636");

  script_name(english:"RHEL 6 : kernel (RHSA-2015:2636)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way the Linux kernel's file system
implementation handled rename operations in which the source was
inside and the destination was outside of a bind mount. A privileged
user inside a container could use this flaw to escape the bind mount
and, potentially, escalate their privileges on the system.
(CVE-2015-2925, Important)

* It was found that the x86 ISA (Instruction Set Architecture) is
prone to a denial of service attack inside a virtualized environment
in the form of an infinite loop in the microcode due to the way
(sequential) delivering of benign exceptions such as #AC (alignment
check exception) and #DB (debug exception) is handled. A privileged
user inside a guest could use these flaws to create denial of service
conditions on the host kernel. (CVE-2015-5307, CVE-2015-8104,
Important)

* A race condition flaw was found in the way the Linux kernel's IPC
subsystem initialized certain fields in an IPC object structure that
were later used for permission checking before inserting the object
into a globally visible list. A local, unprivileged user could
potentially use this flaw to elevate their privileges on the system.
(CVE-2015-7613, Important)

* It was found that the Linux kernel's keys subsystem did not
correctly garbage collect uninstantiated keyrings. A local attacker
could use this flaw to crash the system or, potentially, escalate
their privileges on the system. (CVE-2015-7872, Important)

Red Hat would like to thank Ben Serebrin of Google Inc. for reporting
the CVE-2015-5307 issue.

This update also fixes the following bugs :

* Previously, Human Interface Device (HID) ran a report on an
unaligned buffer, which could cause a page fault interrupt and an oops
when the end of the report was read. This update fixes this bug by
padding the end of the report with extra bytes, so the reading of the
report never crosses a page boundary. As a result, a page fault and
subsequent oops no longer occur. (BZ#1268203)

* The NFS client was previously failing to detect a directory loop for
some NFS server directory structures. This failure could cause NFS
inodes to remain referenced after attempting to unmount the file
system, leading to a kernel crash. Loop checks have been added to VFS,
which effectively prevents this problem from occurring. (BZ#1272858)

* Due to a race whereby the nfs_wb_pages_cancel() and
nfs_commit_release_pages() calls both removed a request from the
nfs_inode struct type, the kernel panicked with negative
nfs_inode.npages count. The provided upstream patch performs the
required serialization by holding the inode i_lock over the check of
PagePrivate and locking the request, thus preventing the race and
kernel panic from occurring. (BZ#1273721)

* Due to incorrect URB_ISO_ASAP semantics, playing an audio file using
a USB sound card could previously fail for some hardware
configurations. This update fixes the bug, and playing audio from a
USB sound card now works as expected. (BZ#1273916)

* Inside hugetlb, region data structures were protected by a
combination of a memory map semaphore and a single hugetlb instance
mutex. However, a page-fault scalability improvement backported to the
kernel on previous releases removed the single hugetlb instance mutex
and introduced a new mutex table, making the locking combination
insufficient, leading to possible race windows that could cause
corruption and undefined behavior. This update fixes the problem by
introducing a required spinlock to the region tracking functions for
proper serialization. The problem only affects software using huge
pages through hugetlb interface. (BZ#1274599)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:2636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-2925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-7613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-5307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-7872"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2015-2925", "CVE-2015-5307", "CVE-2015-7613", "CVE-2015-7872", "CVE-2015-8104");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2015:2636");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2636";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-abi-whitelists-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-devel-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-devel-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-devel-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-headers-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-headers-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-debuginfo-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-debuginfo-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-573.12.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-573.12.1.el6")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
