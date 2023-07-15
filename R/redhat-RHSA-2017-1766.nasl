#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1766. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101799);
  script_version("3.12");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-7895");
  script_xref(name:"RHSA", value:"2017:1766");

  script_name(english:"RHEL 7 : kernel (RHSA-2017:1766)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.2
Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* The NFSv2 and NFSv3 server implementations in the Linux kernel
through 4.10.13 lacked certain checks for the end of a buffer. A
remote attacker could trigger a pointer-arithmetic error or possibly
cause other unspecified impacts using crafted requests related to
fs/nfsd/nfs3xdr.c and fs/nfsd/nfsxdr.c. (CVE-2017-7895, Important)

Red Hat would like to thank Ari Kauppi for reporting this issue.

Bug Fix(es) :

* Previously, a race condition between Linux kernel module error
handling and kprobe registration code existed in the Linux kernel. The
protection that was applied during module error handling code could be
overridden by kprobe registration code before the module was
deallocated. Consequently, the mapped page could be freed and become
not 'writable'. When this page was later accessed, a page fault
occurred, which led to a kernel panic. This update fixes the race
condition, and the kernel no longer panics due to this bug.
(BZ#1454683)

* Due to a race with another NFS mount, the nfs41_walk_client_list()
function previously established a lease on the nfs_client pointer
before the check for trunking was finished. This update ensures the
processes follow the correct order and the race no longer occurs in
this scenario. (BZ#1447383)

* If a duplicate IPv6 address or an issue setting an address was
present in the net/ipv6/addrconf.c file, a race condition occurred
that could cause an IFP refcount leak. Attempts to unregister a
netdevice then produced 'Unregister Netdevice Failed' error messages.
The provided patch fixes this bug, and race conditions no longer occur
in this situation. (BZ#1449103)

* Previously, subtracting from vCPU threads could cause a steal_time
overflow on QEMU live migration. This update makes sure steal_time
accumulation to vCPU entry time is moved before copying steal_time
data to QEMU guest, thus fixing this bug. (BZ#1274919)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:1766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7895"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/19");
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
if (! preg(pattern:"^7\.2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.2", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-7895");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2017:1766");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1766";
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
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"kernel-abi-whitelists-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debug-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-devel-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", reference:"kernel-doc-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-headers-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-kdump-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"perf-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"perf-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"perf-debuginfo-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"python-perf-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"python-perf-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-327.58.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"2", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-327.58.1.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
