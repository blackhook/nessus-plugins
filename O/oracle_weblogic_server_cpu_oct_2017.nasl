#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103935);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-10152",
    "CVE-2017-10271",
    "CVE-2017-10334",
    "CVE-2017-10336",
    "CVE-2017-10352"
  );
  script_bugtraq_id(101304, 101351, 101392);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/10");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (October 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is
affected by multiple vulnerabilities");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e07fa0e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2017 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10352");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle Weblogic Server Deserialization RCE - AsyncResponseService');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Oracle WebLogic Server";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ohome = install["Oracle Home"];
subdir = install["path"];
version = install["version"];

fix = NULL;
fix_ver = NULL;

# individual security patches
if (version =~ "^10\.3\.6\.")
{
  fix_ver = "10.3.6.0.171017";
  fix = "26519424";
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = "12.1.3.0.171017";
  fix = "26519417";
}
else if (version =~ "^12\.2\.1\.1($|[^0-9])")
{
  fix_ver = "12.2.1.1.171017";
  fix = "26519400";
}
else if (version =~ "^12\.2\.1\.2($|[^0-9])")
{
  fix_ver = "12.2.1.2.171017";
  fix = "26485996";
}

if (!isnull(fix_ver) && ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1)
{
  os = get_kb_item_or_exit("Host/OS");
  if ('windows' >< tolower(os))
  {
    port = get_kb_item("SMB/transport");
    if (!port) port = 445;
  }
  else port = 0;

  report =
    '\n  Oracle home    : ' + ohome +
    '\n  Install path   : ' + subdir +
    '\n  Version        : ' + version +
    '\n  Required Patch : ' + fix +
    '\n';
  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);
