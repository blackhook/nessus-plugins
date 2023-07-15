#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0154.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103592);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_name(english:"OracleVM 3.4 : nss (OVMSA-2017-0154)");
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

  - Added nss-vendor.patch to change vendor

  - Temporarily disable some tests until expired
    PayPalEE.cert is renewed

  - Backport patch to simplify transcript calculation for
    CertificateVerify"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-September/000782.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5270bb1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss / nss-sysinit / nss-tools packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"nss-3.28.4-4.0.1.el6_9")) flag++;
if (rpm_check(release:"OVS3.4", reference:"nss-sysinit-3.28.4-4.0.1.el6_9")) flag++;
if (rpm_check(release:"OVS3.4", reference:"nss-tools-3.28.4-4.0.1.el6_9")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-sysinit / nss-tools");
}
