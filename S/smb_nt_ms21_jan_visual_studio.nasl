#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144977);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id(
    "CVE-2020-26870",
    "CVE-2021-1651",
    "CVE-2021-1680",
    "CVE-2021-1723"
  );
  script_xref(name:"MSKB", value:"4584787");
  script_xref(name:"MSFT", value:"MS21-4584787");
  script_xref(name:"IAVA", value:"2021-A-0021");
  script_xref(name:"CEA-ID", value:"CEA-2021-0001");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (January 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security
updates. It is, therefore, affected by multiple
vulnerabilities:

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2021-1651, CVE-2021-1680)

  - A denial of service (DoS) vulnerability. An attacker can
    exploit this issue to cause the affected component to
    deny system or application services. (CVE-2021-1723)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2020-26870)");
  # https://support.microsoft.com/en-us/help/4584787/security-update-for-visual-studio-2015-update-3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?459d683d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  - Install KB4584787 for Visual Studio 2015
  - Update 15.9.31 for Visual Studio 2017
  - Update 16.0.22 for Visual Studio 2019
  - Update 16.4.17 for Visual Studio 2019
  - Update 16.7.10 for Visual Studio 2019
  - Update 16.8.4 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1651");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('install_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');

get_kb_item_or_exit('installed_sw/Microsoft Visual Studio');

port = kb_smb_transport();
appname = 'Microsoft Visual Studio';

installs = get_installs(app_name:appname, exit_if_not_found:TRUE);

report = '';

foreach install (installs[1])
{
  version = install['version'];
  path = install['path'];
  prod = install['product_version'];

  fix = '';

  # https://docs.microsoft.com/en-us/visualstudio/install/visual-studio-build-numbers-and-release-dates?view=vs-2017
  #
  # VS 2017
  if (prod == '2017')
  {
    fix = '15.9.28307.1342';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # https://docs.microsoft.com/en-us/visualstudio/install/visual-studio-build-numbers-and-release-dates?view=vs-2019
  #
  # VS 2019 Version 16.0
  else if (prod == '2019' && version =~ "^16\.0\.")
  {
    fix = '16.0.28803.916';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.4
  else if (prod == '2019' && version =~ "^16\.[1-4]\.")
  {
    fix = '16.4.30816.121';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.4
  else if (prod == '2019' && version =~ "^16\.[5-7]\.")
  {
    fix = '16.7.30816.78';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.8
  else if (prod == '2019' && version =~ "^16\.8\.")
  {
    fix = '16.8.30907.101';
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

hotfix_check_fversion_end();

if (empty(report))
  audit(AUDIT_INST_VER_NOT_VULN, appname);

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
