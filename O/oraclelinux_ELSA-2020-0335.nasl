#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0335 and 
# Oracle Linux Security Advisory ELSA-2020-0335 respectively.
#

include("compat.inc");

if (description)
{
  script_id(133590);
  script_version("1.2");
  script_cvs_date("Date: 2020/02/12");

  script_cve_id("CVE-2019-14865");
  script_xref(name:"RHSA", value:"2020:0335");

  script_name(english:"Oracle Linux 8 : grub2 (ELSA-2020-0335)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2020:0335 :

An update for grub2 is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The grub2 packages provide version 2 of the Grand Unified Boot Loader
(GRUB), a highly configurable and customizable boot loader with
modular architecture. The packages support a variety of kernel
formats, file systems, computer architectures, and hardware devices.

Security Fix(es) :

* grub2: grub2-set-bootflag utility causes grubenv corruption
rendering the system non-bootable (CVE-2019-14865)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2020-February/009624.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected grub2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/10");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-common-2.02-78.0.3.el8_1.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-aa64-modules-2.02-78.0.3.el8_1.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-ia32-2.02-78.0.3.el8_1.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-ia32-cdboot-2.02-78.0.3.el8_1.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-ia32-modules-2.02-78.0.3.el8_1.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-x64-2.02-78.0.3.el8_1.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-x64-cdboot-2.02-78.0.3.el8_1.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-efi-x64-modules-2.02-78.0.3.el8_1.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-pc-2.02-78.0.3.el8_1.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-pc-modules-2.02-78.0.3.el8_1.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-tools-2.02-78.0.3.el8_1.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-tools-efi-2.02-78.0.3.el8_1.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-tools-extra-2.02-78.0.3.el8_1.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"grub2-tools-minimal-2.02-78.0.3.el8_1.1")) flag++;


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
