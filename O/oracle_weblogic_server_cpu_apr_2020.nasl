#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135680);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/07");

  script_cve_id(
    "CVE-2019-16943",
    "CVE-2019-17359",
    "CVE-2019-17571",
    "CVE-2020-2766",
    "CVE-2020-2798",
    "CVE-2020-2801",
    "CVE-2020-2811",
    "CVE-2020-2828",
    "CVE-2020-2829",
    "CVE-2020-2867",
    "CVE-2020-2869",
    "CVE-2020-2883",
    "CVE-2020-2884",
    "CVE-2020-2963"
  );
  script_xref(name:"IAVA", value:"2020-A-0153");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2020-0045");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the CPUApr2020 advisory.

  - A remote code execution vulnerability exists in the Log4j SocketServer class due to unsafe deserialization of
    untrusted data. An unauthenticated, remote attacker can exploit this to remotely execute arbitrary code when
    combined with a deserialization gadget when listening to untrusted network traffic for log data. This affects Log4j
    versions up to 1.2 up to 1.2.17. (CVE-2019-17571)

  - An information disclosure vulnerability exists in the Console component. An unauthenticated, remote attacker can
    exploit this to gain unauthorized read access to a subset of Oracle WebLogic Server accessible data. (CVE-2020-2766)

  - A vulnerability in the WLS Web Services component exists. An authenticated, remote attacker can exploit this via T3
    to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle
    WebLogic Server. (CVE-2020-2798)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2884");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'WebLogic Server Deserialization RCE BadAttributeValueExpException ExtComp');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

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
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include('audit.inc');
include('install_func.inc');

app_name = 'Oracle WebLogic Server';

os = get_kb_item_or_exit('Host/OS');
if ('windows' >< tolower(os))
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;
}
else port = 0;

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];

fix = NULL;
fix_ver = NULL;

if (version =~ "^12\.2\.1\.4($|[^0-9])")
{
  fix_ver = '12.2.1.4.200228';
  fix = make_list('30970477', '30761841', '31101341');
}

else if (version =~ "^12\.2\.1\.3($|[^0-9])")
{
  fix_ver = '12.2.1.3.200227';
  fix = make_list('30965714');
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = '12.1.3.0.200414';
  fix = make_list('30857795');
}
else if (version =~ "^10\.3\.6\.")
{
  fix_ver = '10.3.6.0.200414';
  fix = make_list('Q3ZB');
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

