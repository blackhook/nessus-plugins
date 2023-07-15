#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141807);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/24");

  script_cve_id(
    "CVE-2019-17267",
    "CVE-2020-9488",
    "CVE-2020-11022",
    "CVE-2020-14750",
    "CVE-2020-14757",
    "CVE-2020-14820",
    "CVE-2020-14825",
    "CVE-2020-14841",
    "CVE-2020-14859",
    "CVE-2020-14882",
    "CVE-2020-14883"
  );
  script_xref(name:"IAVA", value:"2020-A-0478");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2020-0132");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of WebLogic Server installed on the remote host is affected by multiple vulnerabilities as referenced in
the October 2020 CPU advisory.

  - An unspecified vulnerability exists in the Console component. An unauthenticated, remote attacker with
    network access via HTTP can exploit this issue to compromise the server. Successful attacks of this 
    vulnerability can result in takeover of Oracle WebLogic Server. (CVE-2020-14750, CVE-2020-14882)

  - An unspecified vulnerability exists in the Core component. An unauthenticated, remote attacker can exploit 
    this issue via the IIOP and T3 protocols to compromise the server. Successful attacks of this
    vulnerability can result in takeover of Oracle WebLogic Server. (CVE-2020-14859)

  - An unspecified vulnerability exists in the Core component. An unauthenticated, remote attacker can exploit
    this issue via the IIOP protocol to compromise the server. Successful attacks of this vulnerability can
    result in takeover of Oracle WebLogic Server. (CVE-2020-14841)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/alert-cve-2020-14750.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory and the Oracle Security
Alert advisory for CVE-2020-14750.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14882");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle WebLogic Server Administration Console Handle RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_ports("installed_sw/Oracle WebLogic Server", "installed_sw/Oracle Data Integrator Embedded Weblogic Server");

  exit(0);
}

include('audit.inc');
include('install_func.inc');

app_name = 'Oracle WebLogic Server';
app_name_odi = 'Oracle Data Integrator Embedded Weblogic Server';

os = get_kb_item_or_exit('Host/OS');
if ('windows' >< tolower(os))
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;
}
else port = 0;

normal_installs = get_installs(app_name:app_name, port:port, exit_if_not_found:FALSE);
odi_installs = get_installs(app_name:app_name_odi, port:port, exit_if_not_found:FALSE);
all_installs = {};

if (odi_installs[0] == IF_OK)
  all_installs = odi_installs[1];

if (normal_installs[0] == IF_OK)
  all_installs = make_list2(all_installs, normal_installs[1]);

if (empty(all_installs))
  audit(AUDIT_NOT_INST, app_name + ' or ' + app_name_odi);

install = branch(all_installs);
version = install['version'];

fix = NULL;
fix_ver = NULL;

if (version =~ "^14\.1\.1\.0($|[^0-9])")
{
  fix_ver = '14.1.1.0.200930';
  fix = make_list('31957062', '32097180');
}
else if (version =~ "^12\.2\.1\.4($|[^0-9])")
{
  fix_ver = '12.2.1.4.201001';
  fix = make_list('31960985', '32097167');
}
else if (version =~ "^12\.2\.1\.3($|[^0-9])")
{
  fix_ver = '12.2.1.3.201001';
  fix = make_list('31961038', '32097173');
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = '12.1.3.0.201020';
  fix = make_list('31656851', '32097177');
}
else if (version =~ "^10\.3\.6\.")
{
  fix_ver = '10.3.6.0.201020';
  fix = make_list('NA7A', 'KYRS');
}

if (isnull(fix_ver) || ver_compare(ver:version, fix:fix_ver, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install['path']);

else {
  report =
    '\n  Oracle Home    : ' + install['Oracle Home'] +
    '\n  Install path   : ' + install['path'] +
    '\n  Version        : ' + version +
    '\n  Fixes          : ' + join(sep:', ', fix);
  security_report_v4(extra:report, severity:SECURITY_HOLE, port:port);
}

