#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150418);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id("CVE-2021-31957");
  script_xref(name:"IAVA", value:"2021-A-0278-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (June 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing a security update. They are, therefore, affected by a denial of service 
(DoS) vulnerability due to improper handling of client connections. An unauthenticated, remote attacker can exploit 
this issue to cause the applications to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.4#16.4.23
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83268e80");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.7#16.7.16
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30138c7e");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.9#16.9.7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9497ffd6");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.10.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db72b947");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
 - Update 16.4.23 for Visual Studio 2019
 - Update 16.7.16 for Visual Studio 2019
 - Update 16.9.7 for Visual Studio 2019
 - Update 16.10.1 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31957");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/09");

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

var port = kb_smb_transport();
var appname = 'Microsoft Visual Studio';
var installs = get_installs(app_name:appname, exit_if_not_found:TRUE);
var report = '';

foreach var install (installs[1])
{
  var version = install['version'];
  var path = install['path'];
  var prod = install['product_version'];
  var fix = '';
  
  if (prod == '2019') 
  {
    # VS 2019 Version 16.0-4
    if (version =~ "^16\.[0-4]\.") 
    {
      fix = '16.4.31327.141';
      if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
      {
        report +=
          '\n  Path              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : ' + fix +
          '\n';
      }
    }
    # VS 2019 Version 16.5-7
    else if (version =~ "^16\.[5-7]\.")
    {
      fix = '16.7.31327.30';
      if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
      {
        report +=
          '\n  Path              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : ' + fix +
          '\n';
      }
    }
    # VS 2019 Version 16.8-9
    else if (version =~ "^16\.[89]\.")
    {
      fix = '16.9.31328.270';
      if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
      {
        report +=
          '\n  Path              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : ' + fix +
          '\n';
      }
    }
    # VS 2019 Version 16.10
    else if (version =~ "^16\.10\.")
    {
      fix = '16.10.31402.337';
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
}

if (empty(report))
  audit(AUDIT_INST_VER_NOT_VULN, appname);

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
