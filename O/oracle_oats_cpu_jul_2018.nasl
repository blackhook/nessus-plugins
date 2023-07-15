#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111210);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-5645", "CVE-2018-1275");
  script_bugtraq_id(97702, 103771);

  script_name(english:"Oracle Application Testing Suite Multiple Vulnerabilities (April / July 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Application Testing Suite installed on the
remote host is affected by multiple vulnerabilities : 

  - A remote code execution vulnerability exists in Apache Log4j 2.x
    before 2.8.2 due to the ability to receive serialized log events
    from another application. An unauthenticated, remote attacker can
    exploit this, via a specially crafted message, to execute
    arbitrary code on the remote host. (CVE-2017-5645)

  - A remote code execution vulnerability exists in Spring Framework
    due to the exposure of STOMP over WebSocket endpoints with a
    simple, in-memory STOMP broker through the spring-messaging
    module. An unauthenticated, remote attacker can exploit this,
    via a specially crafted message, to execute arbitrary code on the
    remote host. (CVE-2018-1275)");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76507bf8");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50f36723");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April / July 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1275");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_testing_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_application_testing_suite_installed.nbin");
  script_require_keys("installed_sw/Oracle Application Testing Suite");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("install_func.inc");

app_name = "Oracle Application Testing Suite";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ohome = install["Oracle Home"];
subdir = install["path"];
version = install["version"];

fix = NULL;
fix_ver = NULL;

# individual security patches
if (version =~ "^13\.2\.0\.1\.")
{
  fix_ver = "13.2.0.1.215";
  fix = "27794987";
}
else if (version =~ "^13\.1\.0\.1\.")
{
  fix_ver = "13.1.0.1.416";
  fix = "27794982";
}
else if (version =~ "^12\.5\.0\.3\.")
{
  fix_ver = "12.5.0.3.1059";
  fix = "27794971";
}

if (
  # Vulnerble versions that have patch 
  (!isnull(fix_ver) && ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1) ||
  # Vulnerable versions that require upgrade and then patch
  (ver_compare(ver:version, fix:'12.5.0.3.0', strict:FALSE) == -1)
  )
{
  report =
    '\n  Oracle home    : ' + ohome +
    '\n  Install path   : ' + subdir +
    '\n  Version        : ' + version;
  if (!isnull(fix_ver)) 
  {
    report += 
      '\n  Required patch : ' + fix +
      '\n';
  }
  else
  {
    report += 
      '\n  Upgrade to 12.5.0.3 / 13.1.0.1 / 13.2.0.1 and apply the ' +
      'appropriate patch according to the April / July 2018 Oracle ' +
      'Critical Patch Update advisory.' +
      '\n';
  }
  security_report_v4(extra:report, port:0, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);
