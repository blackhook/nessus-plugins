#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2010-2009.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68173);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2010-2942",
    "CVE-2010-3067",
    "CVE-2010-3477",
    "CVE-2010-3904"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"Oracle Linux 5 : Unbreakable Enterprise kernel (ELSA-2010-2009)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Description of changes:

Following Security bug are fixed in this errata

CVE-2010-3904
When copying data to userspace, the RDS protocol failed to verify that 
the user-provided address was a valid
userspace address.  A local unprivileged user could issue specially 
crafted socket calls to write arbitrary
values into kernel memory and potentially escalate privileges to root.

CVE-2010-3067
Integer overflow in the do_io_submit function in fs/aio.c in the Linux 
kernel before 2.6.36-rc4-next-20100915
allows local users to cause a denial of service or possibly have 
unspecified other impact via crafted use of
the io_submit system call.

CVE-2010-3477
The tcf_act_police_dump function in net/sched/act_police.c in the 
actions implementation in the network queueing
functionality in the Linux kernel before 2.6.36-rc4 does not properly 
initialize certain structure members, which
allows local users to obtain potentially sensitive information from 
kernel memory via vectors involving a dump
operation. NOTE: this vulnerability exists because of an incomplete fix 
for CVE-2010-2942.

kernel:

[2.6.32-100.21.1.el5]
- [rds] fix access issue with rds (Chris Mason) {CVE-2010-3904}
- [fuse] linux-2.6.32-fuse-return-EGAIN-if-not-connected-bug-10154489.patch
- [net] linux-2.6.32-net-sched-fix-kernel-leak-in-act_police.patch
- [aio] 
linux-2.6.32-aio-check-for-multiplication-overflow-in-do_io_subm.patch

ofa:

[1.5.1-4.0.23]
- Fix rds permissions checks during copies

[1.5.1-4.0.21]
- Update to BXOFED 1.5.1-1.3.6-5");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2010-October/001707.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected unbreakable enterprise kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-2942");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_page_copy_user Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-100.21.1.el5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  cve_list = make_list("CVE-2010-2942", "CVE-2010-3067", "CVE-2010-3477", "CVE-2010-3904");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2010-2009");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

kernel_major_minor = get_kb_item("Host/uname/major_minor");
if (empty_or_null(kernel_major_minor)) exit(1, "Unable to determine kernel major-minor level.");
expected_kernel_major_minor = "2.6";
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, "running kernel level " + expected_kernel_major_minor + ", it is running kernel level " + kernel_major_minor);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-2.6.32-100.21.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-debug-2.6.32-100.21.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-100.21.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-devel-2.6.32-100.21.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-doc-2.6.32-100.21.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-firmware-2.6.32-100.21.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-headers-2.6.32-100.21.1.el5")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"ofa-2.6.32-100.21.1.el5-1.5.1-4.0.23")) flag++;


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
