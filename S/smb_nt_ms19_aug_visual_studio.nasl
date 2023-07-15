#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.


include("compat.inc");

if (description)
{
  script_id(127855);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/27");

  script_cve_id("CVE-2019-1211");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (August 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing a security
update. It is, therefore, affected by the following
vulnerability :

  - An elevation of privilege vulnerability exists in Git
    for Visual Studio when it improperly parses
    configuration files. An attacker who successfully
    exploited the vulnerability could execute code in the
    context of another local user.  (CVE-2019-1211)");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes-v15.0#15.0.26228.96
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?288bf144");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.15_SAR_1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53e51634");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.0#16.0.7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a81d919");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.2.2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30e9f320");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1211");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('misc_func.inc');
include('install_func.inc');
include('global_settings.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

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

  # Visual Studio 2017 (15.0)
  if (prod == '2017' && version =~ '^15\\.0\\.')
  {
    fix = '15.0.26228.96';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # Visual Studio 2017 (15.9)
  else if (prod == '2017' && version =~ '^15\\.[1-9]\\.')
  {
    fix = '15.9.28307.812';

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

if (empty(report)) audit(AUDIT_INST_VER_NOT_VULN, appname);
security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
