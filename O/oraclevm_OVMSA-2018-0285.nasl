#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0285.
#

include("compat.inc");

if (description)
{
  script_id(119484);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/27");

  script_cve_id("CVE-2017-8291", "CVE-2018-16509");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/14");

  script_name(english:"OracleVM 3.3 / 3.4 : ghostscript (OVMSA-2018-0285)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - It was found that the fix for CVE-2018-16509 was not
    complete, the missing pieces added into
    ghostscript-CVE-2018-16509.patch

  - Resolves: #1641124 - CVE-2018-16509 ghostscript:
    /invalidaccess bypass after failed restore

  - Added security fix for CVE-2017-8291 (bug #1446063)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-December/000920.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33457c2d"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-December/000919.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fef182f"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected ghostscript package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16509");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ghostscript Failed Restore Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.3", reference:"ghostscript-8.70-24.el6_10.2")) flag++;

if (rpm_check(release:"OVS3.4", reference:"ghostscript-8.70-24.el6_10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript");
}
