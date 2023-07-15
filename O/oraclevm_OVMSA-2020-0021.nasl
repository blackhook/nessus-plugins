#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0021.
#

include("compat.inc");

if (description)
{
  script_id(137170);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2006-4095", "CVE-2007-2241", "CVE-2007-2925", "CVE-2007-2926", "CVE-2007-6283", "CVE-2008-0122", "CVE-2008-1447", "CVE-2009-0025", "CVE-2009-0696", "CVE-2010-0097", "CVE-2010-0290", "CVE-2011-0414", "CVE-2011-1910", "CVE-2011-2464", "CVE-2012-1033", "CVE-2012-1667", "CVE-2012-3817", "CVE-2012-4244", "CVE-2012-5166", "CVE-2012-5688", "CVE-2012-5689", "CVE-2013-2266", "CVE-2013-4854", "CVE-2014-0591", "CVE-2014-8500", "CVE-2015-1349", "CVE-2015-4620", "CVE-2015-5477", "CVE-2015-5722", "CVE-2015-8000", "CVE-2015-8704", "CVE-2016-1285", "CVE-2016-1286", "CVE-2016-2776", "CVE-2016-2848", "CVE-2016-8864", "CVE-2016-9147", "CVE-2017-3136", "CVE-2017-3137", "CVE-2017-3142", "CVE-2017-3143", "CVE-2017-3145", "CVE-2018-5740", "CVE-2018-5743", "CVE-2020-8616", "CVE-2020-8617");
  script_bugtraq_id(19859, 25037, 27283, 30131, 33151, 35848, 37118, 37865, 46491, 48007, 48566, 51898, 53772, 54658, 55522, 55852, 56817, 57556, 58736, 61479, 64801, 71590, 72673, 75588);

  script_name(english:"OracleVM 3.3 / 3.4 : bind (OVMSA-2020-0021)");
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
OVMSA-2020-0021 for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2020-June/000984.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2020-June/000981.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2020-June/000982.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected bind-libs / bind-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0122");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(16, 189, 200, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.3", reference:"bind-libs-9.8.2-0.68.rc1.el6_10.7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"bind-utils-9.8.2-0.68.rc1.el6_10.7")) flag++;

if (rpm_check(release:"OVS3.4", reference:"bind-libs-9.8.2-0.68.rc1.el6_10.7")) flag++;
if (rpm_check(release:"OVS3.4", reference:"bind-utils-9.8.2-0.68.rc1.el6_10.7")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind-libs / bind-utils");
}
