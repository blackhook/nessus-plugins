#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0399. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107187);
  script_version("1.9");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2017-8824");
  script_xref(name:"RHSA", value:"2018:0399");

  script_name(english:"RHEL 7 : kernel (RHSA-2018:0399)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix six bugs are now available for Red
Hat Enterprise Linux 7.3 Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* kernel: Use-after-free vulnerability in DCCP socket (CVE-2017-8824,
Important)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* Previously, there were cases where the ethtool kernel code called
the vzalloc() function, which allocates virtually contiguous memory
with zero fill, with a size of zero. Consequently, running the ethtool
-d command to query hardware registers led to the following dmesg
error :

ethtool: vmalloc: allocation failure: 0 bytes,
mode:0x24080c2(GFP_KERNEL| __GFP_HIGHMEM|__GFP_ZERO)

With this update, the kernel code has been fixed to avoid the invalid
vzalloc call, and the dmesg error no longer occurs. (BZ#1530128)

* Previously, if an NFSv4 mount operation encountered an NFS client
structure that has not completed initialization, the trunking
detection logic waited for the operation to complete. Consequently, if
a concurrent NFSv4 mount operation added another item to the list of
NFS client structures, this client was not able to begin
initialization, because it was waiting on the mutex held by the other
process, and a deadlock occurred. This update fixes NFS to wait until
the NFS client structure initialization is completed before adding a
new structure to the list. As a result, the deadlock no longer occurs,
and the NFS client can now initialize as expected under the described
circumstances. (BZ#1530134)

* If the Extensible Firmware Interface (EFI) created a new set of page
tables and mapped a segment of code at a low address, the operating
system (OS) failed to boot. This update fixes the EFI code, and the OS
now boots as expected under the described circumstances. (BZ#1535880)

* The Return Trampoline (Retpoline) mechanism mitigates the branch
target injection, also known as the Spectre variant 2 vulnerability.
With this update, Retpoline has been implemented into the Red Hat
Enterprise Linux kernel. (BZ#1539648)

* This update adds a new line to the /proc/cpuinfo file to show all
available facilities that are reported by the stfle instruction on IBM
z systems. (BZ #1540088)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:0399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-8824"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  cve_list = make_list("CVE-2017-8824");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2018:0399");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:0399";
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
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", reference:"kernel-abi-whitelists-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debug-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debug-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-devel-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-devel-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", reference:"kernel-doc-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-headers-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-headers-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-kdump-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-tools-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"perf-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"perf-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"perf-debuginfo-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"python-perf-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"python-perf-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-514.44.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-514.44.1.el7")) flag++;

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
