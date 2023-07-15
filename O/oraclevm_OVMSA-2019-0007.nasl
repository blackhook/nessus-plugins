#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2019-0007.
#

include("compat.inc");

if (description)
{
  script_id(122087);
  script_version("1.4");
  script_cvs_date("Date: 2020/02/12");

  script_cve_id("CVE-2017-12153", "CVE-2018-17972", "CVE-2018-3639");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2019-0007) (Spectre)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - x86/bugs: Fix the AMD SSBD usage of the SPEC_CTRL MSR
    (Tom Lendacky) [Orabug: 28870524] (CVE-2018-3639)

  - x86/bugs: Add AMD's SPEC_CTRL MSR usage (Konrad
    Rzeszutek Wilk) [Orabug: 28870524] (CVE-2018-3639)

  - x86/cpufeatures: rename X86_FEATURE_AMD_SSBD to
    X86_FEATURE_LS_CFG_SSBD (Mihai Carabas) [Orabug:
    28870524] (CVE-2018-3639)

  - Make file credentials available to the seqfile
    interfaces (Linus Torvalds) [Orabug: 29114879]
    (CVE-2018-17972)

  - proc: restrict kernel stack dumps to root (Jann Horn)
    [Orabug: 29114879] (CVE-2018-17972)

  - x86/speculation: Clean up retpoline code in bugs.c
    (Alejandro Jimenez) [Orabug: 29211617]

  - x86, modpost: Replace last remnants of RETPOLINE with
    CONFIG_RETPOLINE (WANG Chao) [Orabug: 29211617]

  - x86/build: Fix compiler support check for
    CONFIG_RETPOLINE (Masahiro Yamada) [Orabug: 29211617]

  - x86/retpoline: Remove minimal retpoline support
    (Zhenzhong Duan) [Orabug: 29211617]

  - x86/retpoline: Make CONFIG_RETPOLINE depend on compiler
    support (Zhenzhong Duan) [Orabug: 29211617]

  - nl80211: check for the required netlink attributes
    presence (Vladis Dronov) [Orabug: 29245533]
    (CVE-2017-12153) (CVE-2017-12153)

  - scsi: lpfc: Fix PT2PT PRLI reject (reapply patch) (James
    Smart) [Orabug: 29281346]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2019-February/000928.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66ac1732"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3639");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.25.1.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.25.1.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
