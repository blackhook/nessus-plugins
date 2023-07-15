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
  script_id(136515);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id("CVE-2020-1108", "CVE-2020-1161");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (May 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities :

  - A denial of service vulnerability exists when .NET Core or .NET
    Framework improperly handles web requests. An attacker who
    successfully exploited this vulnerability could cause a denial of
    service against a .NET Core or .NET Framework web application. The
    vulnerability can be exploited remotely, without authentication.
    (CVE-2020-1108)

  - A denial of service vulnerability exists when ASP.NET Core
    improperly handles web requests. An attacker who successfully
    exploited this vulnerability could cause a denial of service against
    an ASP.NET Core web application. The vulnerability can be exploited
    remotely, without authentication. (CVE-2020-1161)");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  - Update 15.9.23 for Visual Studio 2017
  - Update 16.0.14 for Visual Studio 2019
  - Update 16.4.8 for Visual Studio 2019
  - Update 16.5.5 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1108");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
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

get_kb_item_or_exit('installed_sw/Microsoft Visual Studio');

port = get_kb_item("SMB/transport");
appname = 'Microsoft Visual Studio';

installs = get_installs(app_name:appname, exit_if_not_found:TRUE);

report = '';

foreach install (installs[1])
{
  version = install['version'];
  path = install['path'];
  prod = install['product_version'];

  fix = '';

  # VS 2017 Version 15.9.23
  if (prod == '2017' && version =~ '^15\\.[1-9]\\.')
  {
    fix = '15.9.28307.1146';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.0.14
  else if (prod == '2019' && version =~ '^16\\.0\\.')
  {
    fix = '16.0.28803.735';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.4.8
  else if (prod == '2019' && version =~ '^16\\.4\\.')
  {
    fix = '16.4.30107.140';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2019 Version 16.5.5
  else if (prod == '2019' && version =~ '^16\\.5\\.')
  {
    fix = '16.5.30104.148';
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

if (empty(report))
  audit(AUDIT_INST_VER_NOT_VULN, appname);

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
