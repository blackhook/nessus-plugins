#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2387. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111728);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2018-3620", "CVE-2018-3639", "CVE-2018-3646");
  script_xref(name:"RHSA", value:"2018:2387");

  script_name(english:"RHEL 7 : kernel (RHSA-2018:2387) (Foreshadow) (Spectre)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.4
Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* Modern operating systems implement virtualization of physical memory
to efficiently use available system resources and provide inter-domain
protection through access control and isolation. The L1TF issue was
found in the way the x86 microprocessor designs have implemented
speculative execution of instructions (a commonly used performance
optimisation) in combination with handling of page-faults caused by
terminated virtual to physical address resolving process. As a result,
an unprivileged attacker could use this flaw to read privileged memory
of the kernel or other processes and/or cross guest/host boundaries to
read host memory by conducting targeted cache side-channel attacks.
(CVE-2018-3620, CVE-2018-3646)

* An industry-wide issue was found in the way many modern
microprocessor designs have implemented speculative execution of Load
& Store instructions (a commonly used performance optimization). It
relies on the presence of a precisely-defined instruction sequence in
the privileged code as well as the fact that memory read from address
to which a recent memory write has occurred may see an older value and
subsequently cause an update into the microprocessor's data cache even
for speculatively executed instructions that never actually commit
(retire). As a result, an unprivileged attacker could use this flaw to
read privileged memory by conducting targeted cache side-channel
attacks. (CVE-2018-3639)

Red Hat would like to thank Intel OSSIRT (Intel.com) for reporting
CVE-2018-3620 and CVE-2018-3646 and Ken Johnson (Microsoft Security
Response Center) and Jann Horn (Google Project Zero) for reporting
CVE-2018-3639.

Bug Fix(es) :

* Previously, configurations with the little-endian variant of IBM
Power Systems CPU architectures and Hard Disk Drives (HDD) designed
according to Nonvolatile Memory Express (NVMe) open standards,
experienced crashes during shutdown or reboot due to race conditions
of CPUs. As a consequence, the sysfs pseudo file system threw a stack
trace report about an attempt to create a duplicate entry in sysfs.
This update modifies the source code so that the irq_dispose_mapping()
function is called first and the msi_bitmap_free_hwirqs() function is
called afterwards. As a result, the race condition no longer appears
in the described scenario. (BZ#1570510)

* When switching from the indirect branch speculation (IBRS) feature
to the retpolines feature, the IBRS state of some CPUs was sometimes
not handled correctly. Consequently, some CPUs were left with the IBRS
Model-Specific Register (MSR) bit set to 1, which could lead to
performance issues. With this update, the underlying source code has
been fixed to clear the IBRS MSR bits correctly, thus fixing the bug.
(BZ#1586147)

* During a balloon reset, page pointers were not correctly initialized
after unmapping the memory. Consequently, on the VMware ESXi
hypervisor with 'Fault Tolerance' and 'ballooning' enabled, the
following messages repeatedly occurred in the kernel log :

[3014611.640148] WARNING: at mm/vmalloc.c:1491 __vunmap+0xd3/0x100()
[3014611.640269] Trying to vfree() nonexistent vm area
(ffffc90000697000)

With this update, the underlying source code has been fixed to
initialize page pointers properly. As a result, the mm/vmalloc.c
warnings no longer occur under the described circumstances.
(BZ#1595600)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/L1TF"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-3620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-3639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-3646"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7\.4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.4", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-3620", "CVE-2018-3639", "CVE-2018-3646");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2018:2387");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:2387";
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
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", reference:"kernel-abi-whitelists-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-debug-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-debug-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-devel-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-devel-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", reference:"kernel-doc-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-headers-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-headers-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-kdump-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-tools-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"perf-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"perf-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"perf-debuginfo-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"python-perf-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"python-perf-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-693.37.4.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-693.37.4.el7")) flag++;

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
