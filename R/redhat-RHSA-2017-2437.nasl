#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2437. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102349);
  script_version("3.10");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2015-8970", "CVE-2016-10200", "CVE-2017-2647", "CVE-2017-8797");
  script_xref(name:"RHSA", value:"2017:2437");

  script_name(english:"RHEL 7 : kernel (RHSA-2017:2437)");
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

* A use-after-free flaw was found in the Linux kernel which enables a
race condition in the L2TPv3 IP Encapsulation feature. A local user
could use this flaw to escalate their privileges or crash the system.
(CVE-2016-10200, Important)

* A flaw was found that can be triggered in keyring_search_iterator in
keyring.c if type->match is NULL. A local user could use this flaw to
crash the system or, potentially, escalate their privileges.
(CVE-2017-2647, Important)

* It was found that the NFSv4 server in the Linux kernel did not
properly validate layout type when processing NFSv4 pNFS LAYOUTGET and
GETDEVICEINFO operands. A remote attacker could use this flaw to
soft-lockup the system and thus cause denial of service.
(CVE-2017-8797, Important)

* The lrw_crypt() function in 'crypto/lrw.c' in the Linux kernel
before 4.5 allows local users to cause a system crash and a denial of
service by the NULL pointer dereference via accept(2) system call for
AF_ALG socket without calling setkey() first to set a cipher key.
(CVE-2015-8970, Moderate)

Red Hat would like to thank Igor Redko (Virtuozzo) and Andrey Ryabinin
(Virtuozzo) for reporting CVE-2017-2647 and Igor Redko (Virtuozzo) and
Vasily Averin (Virtuozzo) for reporting CVE-2015-8970.

Bug Fix(es) :

* When running the LPAR with IBM Power 8 SMT8 mode, system performance
degradation occurred due to the load getting spread across threads
from the same core. The provided patches fix scheduler performance
issues and assure the load is spread across cores, thus improving the
system performance significantly. (BZ#1434853)

* Upon reboot, the bond slave with some network adapter ports became
unresponsive in the backup state and never proceeded to the active
state. As a consequence, the bond slave never transmitted any LACP PDU
and the bond interface was never produced properly. With this update,
the i40e network driver has been fixed for long link-down notification
time and the bond slave now transmits LACP PDUs as expected.
(BZ#1446783)

* When attempting to configure two or more Ethernet adapter cards
using Virtual Function I/O (VFIO) in the KVM guest, subsequent KVM
guests previously failed to boot returning an error message. The
provided patch adds the ability of VFIO to support more than one card
in the KVM guest environment. (BZ#1447718)

* It is possible to define the CPUs in which unbound kworkers can run
by setting a 'mask' in a specific file in the sysfs file system,
helping on CPU isolation. However, this setup did not work properly,
and unbounded kworkers were being activated on CPUs in which they were
set to _NOT_ run. The provided patchset prevents unbound kworkers from
being run on CPUs that are masked, thus fixing this bug. (BZ#1458203)

* Due to a regression, the kernel previously failed to create the
/sys/block/ /devices/enclosure_device symlinks. The provided patch
corrects the call to the scsi_is_sas_rphy() function, which is now
made on the SAS end device, instead of the SCSI device. (BZ#1460204)

* Previously, the system panic occurred when running mkfs.ext4 on
newly created software RAID1 partitions on SATA SDD drives. The
provided patch ensures the ext4 file system is created on the /dev/md0
partition and is mounted there successfully. (BZ#1463359)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-10200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-8797"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/10");
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
  cve_list = make_list("CVE-2015-8970", "CVE-2016-10200", "CVE-2017-2647", "CVE-2017-8797");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2017:2437");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:2437";
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
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", reference:"kernel-abi-whitelists-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debug-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debug-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-devel-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-devel-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", reference:"kernel-doc-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-headers-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-headers-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-kdump-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-tools-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"perf-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"perf-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"perf-debuginfo-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"python-perf-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"python-perf-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-514.28.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-514.28.1.el7")) flag++;

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
