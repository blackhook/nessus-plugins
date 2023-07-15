#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(142694);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id("CVE-2020-17100");
  script_xref(name:"IAVA", value:"2020-A-0519-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (November 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by a tampering vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. They are, therefore, affected by a tampering
vulnerability. The vulnerability exists when the Python Tools for Visual Studio creates the python27 folder. An attacker
who successfully exploited this vulnerability could run processes in an elevated context.");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7ba563f");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8a4791b");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d93e731");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.8.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6acccbd8");
  script_set_attribute(attribute:"solution", value:
"Update the Visual Studio installation to one of the following versions, or later:
  - VS 2017 15.9.29
  - VS 2019 16.0.20
  - VS 2019 16.4.15
  - VS 2019 16.8.0");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17100");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    fix = '15.9.28307.1300';

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
    fix = '16.0.28803.868';
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
    fix = '16.4.30703.110';
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
  else if (prod == '2019' && version =~ "^16\.[5-8]\.")
  {
    fix = '16.8.30709.132';
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

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
