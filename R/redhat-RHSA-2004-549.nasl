#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:549. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15944);
  script_version("1.32");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2004-0136", "CVE-2004-0138", "CVE-2004-0619", "CVE-2004-0685", "CVE-2004-0812", "CVE-2004-0883", "CVE-2004-0949", "CVE-2004-1068", "CVE-2004-1070", "CVE-2004-1071", "CVE-2004-1072", "CVE-2004-1073", "CVE-2004-1191");
  script_xref(name:"RHSA", value:"2004:549");

  script_name(english:"RHEL 3 : kernel (RHSA-2004:549)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues in Red Hat
Enterprise Linux 3 are now available.

The Linux kernel handles the basic functions of the operating system.

This update includes fixes for several security issues :

A missing serialization flaw in unix_dgram_recvmsg was discovered that
affects kernels prior to 2.4.28. A local user could potentially make
use of a race condition in order to gain privileges. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-1068 to this issue.

Paul Starzetz of iSEC discovered various flaws in the ELF binary
loader affecting kernels prior to 2.4.28. A local user could use thse
flaws to gain read access to executable-only binaries or possibly gain
privileges. (CVE-2004-1070, CVE-2004-1071, CVE-2004-1072,
CVE-2004-1073)

A flaw when setting up TSS limits was discovered that affects AMD
AMD64 and Intel EM64T architecture kernels prior to 2.4.23. A local
user could use this flaw to cause a denial of service (crash) or
possibly gain privileges. (CVE-2004-0812)

An integer overflow flaw was discovered in the ubsec_keysetup function
in the Broadcom 5820 cryptonet driver. On systems using this driver, a
local user could cause a denial of service (crash) or possibly gain
elevated privileges. (CVE-2004-0619)

Stefan Esser discovered various flaws including buffer overflows in
the smbfs driver affecting kernels prior to 2.4.28. A local user may
be able to cause a denial of service (crash) or possibly gain
privileges. In order to exploit these flaws the user would require
control of a connected Samba server. (CVE-2004-0883, CVE-2004-0949)

SGI discovered a bug in the elf loader that affects kernels prior to
2.4.25 which could be triggered by a malformed binary. On
architectures other than x86, a local user could create a malicious
binary which could cause a denial of service (crash). (CVE-2004-0136)

Conectiva discovered flaws in certain USB drivers affecting kernels
prior to 2.4.27 which used the copy_to_user function on uninitialized
structures. These flaws could allow local users to read small amounts
of kernel memory. (CVE-2004-0685)

All Red Hat Enterprise Linux 3 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-1068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-1070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-1071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-1072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-1073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2004:549"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-unsupported");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CAN-2004-0136", "CAN-2004-0619", "CAN-2004-0685", "CAN-2004-0812", "CAN-2004-0883", "CAN-2004-0949", "CAN-2004-1068", "CAN-2004-1070", "CAN-2004-1071", "CAN-2004-1072", "CAN-2004-1073", "CVE-2004-0138", "CVE-2004-0619", "CVE-2004-0685", "CVE-2004-0812", "CVE-2004-0883", "CVE-2004-0949", "CVE-2004-1068", "CVE-2004-1070", "CVE-2004-1071", "CVE-2004-1072", "CVE-2004-1073", "CVE-2004-1191");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2004:549");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:549";
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
  if (rpm_check(release:"RHEL3", reference:"kernel-2.4.21-20.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"kernel-BOOT-2.4.21-20.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-doc-2.4.21-20.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-hugemem-2.4.21-20.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-hugemem-unsupported-2.4.21-20.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-smp-2.4.21-20.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"kernel-smp-2.4.21-20.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-smp-unsupported-2.4.21-20.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-20.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-source-2.4.21-20.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-unsupported-2.4.21-20.0.1.EL")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-doc / kernel-hugemem / etc");
  }
}
