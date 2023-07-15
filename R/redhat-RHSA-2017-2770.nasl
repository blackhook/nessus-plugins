#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2770. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103351);
  script_version("3.11");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-7533");
  script_xref(name:"RHSA", value:"2017:2770");

  script_name(english:"RHEL 7 : kernel (RHSA-2017:2770)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.3
Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* A race condition was found in the Linux kernel, present since
v3.14-rc1 through v4.12. The race happens between threads of
inotify_handle_event() and vfs_rename() while running the rename
operation against the same file. As a result of the race the next slab
data or the slab's free list pointer can be corrupted with
attacker-controlled data, which may lead to the privilege escalation.
(CVE-2017-7533, Important)

Red Hat would like to thank Leilei Lin (Alibaba Group), Fan Wu (The
University of Hong Kong), and Shixiong Zhao (The University of Hong
Kong) for reporting this issue.

Bug Fix(es) :

* Previously, the sha1-avx2 optimized hashing, which is used on
processors supporting avx2, under certain conditions miscalculated an
offset. Consequently, a kernel crash occasionally occurred on the NFS
clients or servers using the krb5 security. With this update, the
optimized hashing path for sha1-avx2 has been disabled, and the NFS
clients and servers with krb5 security no longer experience the
miscalculation and subsequent crash. (BZ#1446230)

* When virt boundary limit was set, lots of small bios could not be
merged even though they were contiguous physically. In some workload,
such as mkfs.ntfs, system performance could be ten times degraded. The
proposed patch fixes the bug by allowing to merge these small bios,
which improves performance of mkfs.ntfs on devices significantly.
(BZ#1472674)

* When executing the mkfs.btrfs command to create a btrfs file system
over Non-Volatile Memory Express (NVMe), kernel panic was previously
triggered. The underlying code has been patched to fix this
regression, and btrfs is now created successfully in the described
scenario. (BZ#1472675)

* As a side effect of BZ#147263, the system previously crashed when
creating a container device. The provided patch transforms the
resched_task() function into resched_curr(), and the chance of kernel
crash is thus reduced in the aforementioned situation. (BZ#1473742)

* Due to incorrectly used memory in VXLAN driver (a use-after-free bug
and list corruption), the kernel could previously panic under some
circumstances while bringing the VXLAN interfaces down. The provided
patch fixes the memory corruptions, and the panic no longer occurs in
this situation. (BZ#1474263)

* A race condition could cause the in-flight asynchronous buffers
count (bt_io_count) to become negative. This caused the umount
operation to hang in the xfs_wait_buftarg() function. The provided
patch fixes the buffer I/O accounting release race, and XFS umount no
longer hangs. (BZ#1478253)

* Kernel version 3.10.0-498.el7 separated CPU and TSC frequency and
introduced the x86_platform.calibrate_cpu function pointer which
points by default to the native_calibrate_cpu() function. As a
consequence, time synchronization bugs appeared on Red Hat Enterprise
Linux 7.3 ESXi guest causing a time offset shortly after boot. An
upstream patch has been applied, which sets x86_platform.calibrate_cpu
pointer on ESXi guests to the proper function, thus fixing this bug.
(BZ#1479245)

* A system having more than 128 CPUs could previously experience a
crash during shutdown after the Intelligent Platform Management
Interface (IPMI) service was stopped. The provided patch fixes a race
condition in the IPMI smi_timeout() function, allowing the system to
shut down as expected. (BZ# 1479760)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7533"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7\.3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.3", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-7533");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2017:2770");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:2770";
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
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", reference:"kernel-abi-whitelists-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debug-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debug-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-devel-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-devel-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", reference:"kernel-doc-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-headers-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-headers-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-kdump-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-tools-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"perf-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"perf-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"perf-debuginfo-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"python-perf-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"python-perf-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-514.32.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-514.32.2.el7")) flag++;

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
