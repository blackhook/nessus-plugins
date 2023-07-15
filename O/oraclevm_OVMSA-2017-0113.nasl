#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0113.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100948);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_name(english:"OracleVM 3.3 / 3.4 : glibc (OVMSA-2017-0113)");
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

  - backport rh patch 1047983 from OL7, Orabug 25407655

  - Avoid large allocas in the dynamic linker (#1452711)

  - Fix thread cancellation issues for setmntent and others
    (#1437618)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-June/000739.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-June/000740.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/21");
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
if (! preg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"glibc-2.12-1.209.0.3.el6_9.2")) flag++;
if (rpm_check(release:"OVS3.3", reference:"glibc-common-2.12-1.209.0.3.el6_9.2")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nscd-2.12-1.209.0.3.el6_9.2")) flag++;

if (rpm_check(release:"OVS3.4", reference:"glibc-2.12-1.209.0.3.el6_9.2")) flag++;
if (rpm_check(release:"OVS3.4", reference:"glibc-common-2.12-1.209.0.3.el6_9.2")) flag++;
if (rpm_check(release:"OVS3.4", reference:"glibc-devel-2.12-1.209.0.3.el6_9.2")) flag++;
if (rpm_check(release:"OVS3.4", reference:"glibc-headers-2.12-1.209.0.3.el6_9.2")) flag++;
if (rpm_check(release:"OVS3.4", reference:"nscd-2.12-1.209.0.3.el6_9.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / nscd");
}
