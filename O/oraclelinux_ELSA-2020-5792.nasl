#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5792.
#

include("compat.inc");

if (description)
{
  script_id(139167);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/03");

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel (ELSA-2020-5792)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Description of changes:

[5.4.17-2011.4.6.el7uek]
- Revert 'uek-rpm: Move grub boot menu update to posttrans stage.' (Somasundaram Krishnasamy)  [Orabug: 31358097]

[5.4.17-2011.4.5.el7uek]
- IB/sa: Resolv use-after-free in ib_nl_make_request() (Divya Indi)  [Orabug: 31631527]
- certs: Remove Oracle cert compiled into the kernel (Eric Snowberg)  [Orabug: 31555595]
- acpi: disallow loading configfs acpi tables when locked down (Jason A. Donenfeld)  [Orabug: 31642981]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2020-July/010167.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2020-July/010175.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-5.4.17") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-5.4.17-2011.4.6.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-5.4.17") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-5.4.17-2011.4.6.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-5.4.17") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-5.4.17-2011.4.6.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-5.4.17") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-5.4.17-2011.4.6.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-5.4.17") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-5.4.17-2011.4.6.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-tools-5.4.17") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-tools-5.4.17-2011.4.6.el7uek")) flag++;


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
