#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0044.
#

include("compat.inc");

if (description)
{
  script_id(141374);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/15");

  script_cve_id("CVE-2016-10905", "CVE-2016-10906", "CVE-2017-16528", "CVE-2017-16644", "CVE-2017-8924", "CVE-2017-8925", "CVE-2018-16884", "CVE-2018-20856", "CVE-2018-9415", "CVE-2019-10638", "CVE-2019-10639", "CVE-2019-11487", "CVE-2019-14898", "CVE-2019-15218", "CVE-2019-15505", "CVE-2019-15927", "CVE-2019-16746", "CVE-2019-17075", "CVE-2019-18885", "CVE-2019-19049", "CVE-2019-19052", "CVE-2019-19062", "CVE-2019-19073", "CVE-2019-19535", "CVE-2019-19768", "CVE-2019-19965", "CVE-2019-20054", "CVE-2019-20096", "CVE-2019-20811", "CVE-2019-20812", "CVE-2019-3846", "CVE-2019-3874", "CVE-2019-5108", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2020-10720", "CVE-2020-10732", "CVE-2020-10751", "CVE-2020-10769", "CVE-2020-14314", "CVE-2020-14331", "CVE-2020-1749", "CVE-2020-25212", "CVE-2020-25284", "CVE-2020-25285");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2020-0044)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates : please see Oracle VM Security Advisory
OVMSA-2020-0044 for details."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2020-October/001000.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea0c3926"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2020-October/001002.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3070470"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.43.4.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.43.4.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
