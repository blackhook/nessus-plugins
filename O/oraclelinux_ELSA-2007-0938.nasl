#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0938 and 
# Oracle Linux Security Advisory ELSA-2007-0938 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67579);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/24");

  script_cve_id("CVE-2007-4573");
  script_bugtraq_id(25774);
  script_xref(name:"RHSA", value:"2007:0938");

  script_name(english:"Oracle Linux 3 : kernel (ELSA-2007-0938)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0938 :

Updated kernel packages that fix a security issue in the Red Hat
Enterprise Linux 3 kernel are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

A flaw was found in ia32 emulation affecting users running 64-bit
versions of Red Hat Enterprise Linux on x86_64 architectures. A local
user could use this flaw to gain elevated privileges. (CVE-2007-4573).

Red Hat would like to thank Wojciech Purczynski for reporting this
issue.

Red Hat Enterprise Linux 3 users are advised to upgrade to these
packages, which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-September/000343.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-unsupported");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");
include("ksplice.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  cve_list = make_list("CVE-2007-4573");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2007-0938");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

kernel_major_minor = get_kb_item("Host/uname/major_minor");
if (empty_or_null(kernel_major_minor)) exit(1, "Unable to determine kernel major-minor level.");
expected_kernel_major_minor = "2.4";
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, "running kernel level " + expected_kernel_major_minor + ", it is running kernel level " + kernel_major_minor);

flag = 0;
if (rpm_exists(release:"EL3", rpm:"kernel-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-BOOT-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-BOOT-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-doc-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-doc-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-doc-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-doc-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-hugemem-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-hugemem-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-hugemem-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-smp-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-smp-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-smp-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-smp-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-smp-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-smp-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-source-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-source-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-source-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-source-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-unsupported-2.4.21-52.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-unsupported-2.4.21-52.EL")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
