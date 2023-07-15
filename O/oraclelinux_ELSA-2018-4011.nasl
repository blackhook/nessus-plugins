#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-4011.
#

include("compat.inc");

if (description)
{
  script_id(106040);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/24");

  script_cve_id("CVE-2017-5715", "CVE-2017-5754");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2018-4011) (Meltdown) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[4.1.12-112.14.11.el7uek]
- x86/pti/efi: broken conversion from efi to kernel page table (Pavel 
Tatashin)  [Orabug: 27363926] [Orabug: 27352353]  {CVE-2017-5754}
- x86/spec: Always set IBRS to guest value on VMENTER and host on VMEXIT 
(redux) (Konrad Rzeszutek Wilk)  [Orabug: 27369994]
- x86/IBRS: Make sure we restore MSR_IA32_SPEC_CTRL to a valid value 
(Boris Ostrovsky)  [Orabug: 27362581]
- x86/IBRS/IBPB: Set sysctl_ibrs/ibpb_enabled properly (Boris Ostrovsky) 
  [Orabug: 27363792]
- x86/spec_ctrl: Add missing 'lfence' when IBRS is not supported. 
(Konrad Rzeszutek Wilk)  [Orabug: 27339995]  {CVE-2017-5715}
- x86/entry_64: TRACE_IRQS_OFF before re-enabling. (Jamie Iles) 
[Orabug: 27339995]  {CVE-2017-5715}
- ptrace: remove unlocked RCU dereference. (Jamie Iles)  [Orabug: 
27339995]  {CVE-2017-5715}
- x86/ia32: Adds code hygiene for 32bit SYSCALL instruction entry. 
(Konrad Rzeszutek Wilk)  [Orabug: 27339995]  {CVE-2017-5715}
- x86/ia32: don't save registers on audit call (Konrad Rzeszutek Wilk) 
[Orabug: 27339995]  {CVE-2017-5715}
- x86/spec/ia32: Sprinkle IBRS and RSB at the 32-bit SYSCALL (Konrad 
Rzeszutek Wilk)  [Orabug: 27339995]  {CVE-2017-5715}
- x86/ia32: Move STUFF_RSB And ENABLE_IBRS (Konrad Rzeszutek Wilk) 
[Orabug: 27339995]  {CVE-2017-5715}
- x86/spec: Always set IBRS to guest value on VMENTER and host on 
VMEXIT. (Konrad Rzeszutek Wilk)  [Orabug: 27365544]  {CVE-2017-5715}"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-January/007456.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-January/007457.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  cve_list = make_list("CVE-2017-5715", "CVE-2017-5754");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2018-4011");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

kernel_major_minor = get_kb_item("Host/uname/major_minor");
if (empty_or_null(kernel_major_minor)) exit(1, "Unable to determine kernel major-minor level.");
expected_kernel_major_minor = "4.1";
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, "running kernel level " + expected_kernel_major_minor + ", it is running kernel level " + kernel_major_minor);

flag = 0;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-4.1.12-112.14.11.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-112.14.11.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-112.14.11.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-112.14.11.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-112.14.11.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-112.14.11.el6uek")) flag++;

if (rpm_exists(release:"EL7", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-4.1.12-112.14.11.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-112.14.11.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-112.14.11.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-112.14.11.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-112.14.11.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-112.14.11.el7uek")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
