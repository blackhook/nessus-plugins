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
  script_id(119611);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id("CVE-2018-8599");
  script_xref(name:"MSKB", value:"4469516");
  script_xref(name:"MSFT", value:"MS18-4469516");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (December 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing a security
update. It is, therefore, affected by the following
vulnerability :

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector Service improperly
    impersonates certain file operations. An attacker who
    successfully exploited this vulnerability could gain
    elevated privileges. An attacker with unprivileged
    access to a vulnerable system could exploit this
    vulnerability. The security update addresses the
    vulnerability by ensuring the Diagnostics Hub Standard
    Collector Service properly impersonates file operations.
    (CVE-2018-8599)");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-8599
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1ec68a6");
  # https://support.microsoft.com/en-us/help/4469516/security-update-for-vulnerabilities-in-visual-studio-2015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eaabc286");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes-v15.0#15.0.26228.64
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cc17f68");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?829bdf9f");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4469516 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8599");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio");
  script_require_ports(139, 445, "Host/patch_management_checks");

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
  prod = install['product_version'];

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
    if (ver_compare(ver: fversion, fix: '14.0.27529.0', strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + "Team Tools\DiagnosticsHub\Collector\StandardCollector.Service.exe" +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : 14.0.27529.0' +
        '\n';
    }
  }

  # VS 2017 version 15.0
  else if (prod == '2017' && version =~ '^15\\.0\\.')
  {
    fix = '15.0.26228.64'; 

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2017 version 15.9
  # On 15.7.5, it asks to update to 15.9.4
  else if (prod == '2017' && version =~ '^15\\.[1-9]\\.')
  {
    fix = '15.9.28307.222';

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
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
else
  audit(AUDIT_INST_VER_NOT_VULN, appname);
