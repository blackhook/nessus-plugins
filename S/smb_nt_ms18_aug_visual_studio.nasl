#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(111973);
  script_version("1.7");
  script_cvs_date("Date: 2019/07/02 12:46:54");

  script_cve_id("CVE-2018-0952");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (Aug 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by a privilege 
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security
updates. It is, therefore, affected by a privilege escalation 
vulnerability when Diagnostics Hub Standard Collector allows file 
creation in arbitrary locations. To exploit the vulnerability, an 
attacker would first have to log on to the system. An attacker could 
then run a specially crafted application that could exploit the 
vulnerability and take control of an affected system.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0952
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6d37b67");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes-v15.0#15.0.26228.47
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33226799");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.8SR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb5956d7");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0952");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_visual_studio_installed.nbin");
  script_require_keys("installed_sw/Microsoft Visual Studio");
  script_require_ports(139, 445);

  exit(0);
}
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit('installed_sw/Microsoft Visual Studio');
port = kb_smb_transport();
appname = "Microsoft Visual Studio";

installs = get_installs(app_name:appname, exit_if_not_found:TRUE);

report = '';

foreach install (installs[1])
{
  version = install['version'];
  path = install['path'];
  prod = install['prod'];

  # VS 2015 Up3 - #verified
  # File Check change: using file 'StandardCollector.Service.exe'
  if (version =~ '^14\\.0\\.')
  {
    fver = hotfix_get_fversion(path:path+"Team Tools\DiagnosticsHub\Collector\StandardCollector.Service.exe");
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
    fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: '14.0.27526.0', strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + "Team Tools\DiagnosticsHub\Collector\StandardCollector.Service.exe" +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : 14.0.27526.0' +
        '\n';
    }
  }

  # VS 2017 Preview
  else if (prod == '2017 Preview' && version =~ '^15\\.[0-8]\\.')
  {
    fix = '15.8.27924.0';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version + ' Preview' +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }

  # VS 2017
  else if (prod == '2017' && version =~ '^15\\.[0-8]\\.')
  {
    fix = '15.8.28010.0';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
}


if (report != '')
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
else
  audit(AUDIT_INST_VER_NOT_VULN, appname);
