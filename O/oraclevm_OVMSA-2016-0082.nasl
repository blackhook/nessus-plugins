#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0082.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91419);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5219", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7852", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1550", "CVE-2016-2518");
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"OracleVM 3.3 / 3.4 : ntp (OVMSA-2016-0082)");
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

  - don't allow spoofed packets to demobilize associations
    (CVE-2015-7979, CVE-2016-1547)

  - don't allow spoofed packet to enable symmetric
    interleaved mode (CVE-2016-1548)

  - check mode of new source in config command
    (CVE-2016-2518)

  - make MAC check resilient against timing attack
    (CVE-2016-1550)

  - don't accept server/peer packets with zero origin
    timestamp (CVE-2015-8138)

  - fix crash with reslist command (CVE-2015-7977,
    CVE-2015-7978)

  - fix crash with invalid logconfig command (CVE-2015-5194)

  - fix crash when referencing disabled statistic type
    (CVE-2015-5195)

  - don't hang in sntp with crafted reply (CVE-2015-5219)

  - don't crash with crafted autokey packet (CVE-2015-7691,
    CVE-2015-7692, CVE-2015-7702)

  - fix memory leak with autokey (CVE-2015-7701)

  - don't allow setting driftfile and pidfile remotely
    (CVE-2015-7703)

  - don't crash in ntpq with crafted packet (CVE-2015-7852)

  - add option to set Differentiated Services Code Point
    (DSCP) (#1228314)

  - extend rawstats log (#1242895)

  - fix resetting of leap status (#1243034)

  - report clock state changes related to leap seconds
    (#1242937)

  - allow -4/-6 on restrict lines with mask (#1232146)

  - retry joining multicast groups (#1288534)

  - explain synchronised state in ntpstat man page
    (#1286969)

  - check origin timestamp before accepting KoD RATE packet
    (CVE-2015-7704)

  - allow only one step larger than panic threshold with -g
    (CVE-2015-5300)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-May/000470.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-May/000469.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected ntp / ntpdate packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.3", reference:"ntp-4.2.6p5-10.el6.1")) flag++;
if (rpm_check(release:"OVS3.3", reference:"ntpdate-4.2.6p5-10.el6.1")) flag++;

if (rpm_check(release:"OVS3.4", reference:"ntp-4.2.6p5-10.el6.1")) flag++;
if (rpm_check(release:"OVS3.4", reference:"ntpdate-4.2.6p5-10.el6.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntpdate");
}
