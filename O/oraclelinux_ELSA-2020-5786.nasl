#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5786.
#

include('compat.inc');

if (description)
{
  script_id(139165);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-10713",
    "CVE-2020-14308",
    "CVE-2020-14309",
    "CVE-2020-14310",
    "CVE-2020-14311",
    "CVE-2020-15705",
    "CVE-2020-15706",
    "CVE-2020-15707"
  );
  script_xref(name:"IAVA", value:"2020-A-0349");
  script_xref(name:"CEA-ID", value:"CEA-2020-0061");

  script_name(english:"Oracle Linux 8 : grub2 (ELSA-2020-5786)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Description of changes:

[2.02-82.0.2.el8_2.1]
- Fix CVE-2020-10713, CVE-2020-14308, CVE-2020-14309, CVE-2020-14310, 
CVE-2020-14311,
CVE-2020-15705, CVE-2020-15706, CVE-2020-15707 [Orabug: 31225072]
- Update signing certificate for efi binaries");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2020-July/010174.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected grub2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14309");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10713");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-aa64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-ia32-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-ia32-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-tools-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-common-2.02-82.0.2.el8_2.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-aa64-modules-2.02-82.0.2.el8_2.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-ia32-2.02-82.0.2.el8_2.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-ia32-cdboot-2.02-82.0.2.el8_2.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-ia32-modules-2.02-82.0.2.el8_2.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-x64-2.02-82.0.2.el8_2.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-x64-cdboot-2.02-82.0.2.el8_2.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-x64-modules-2.02-82.0.2.el8_2.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-pc-2.02-82.0.2.el8_2.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-pc-modules-2.02-82.0.2.el8_2.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-tools-2.02-82.0.2.el8_2.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-tools-efi-2.02-82.0.2.el8_2.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-tools-extra-2.02-82.0.2.el8_2.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-tools-minimal-2.02-82.0.2.el8_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2-common / grub2-efi-aa64-modules / grub2-efi-ia32 / etc");
}
