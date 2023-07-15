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
  script_id(123459);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_name(english:"Untrusted Microsoft Office Macro Execution Enabled");

  script_set_attribute(attribute:"synopsis", value:
"A Microsoft Office application installed on the remote host has untrusted
macro execution settings enabled.");
  script_set_attribute(attribute:"description", value:
"A Microsoft Office application installed on the remote host has untrusted
macro execution settings enabled.

Note: This plugin first checks to verify that there are any Microsoft Office
products actually installed. If there are, it will enumerate the registry 
keys that are set when an Office application allows the execution of untrusted
macros. In some in edge cases, the registry settings that allow the execution 
of untrusted macros may still be present and set, even if there are no installed
Microsoft Office products. In this scenario, this plugin will require paranoid 
mode to check these registry keys.");

  script_set_attribute(attribute:"solution", value:
"Disable the macro execution trust settings.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable research analyzed the issue and assigned a score for it.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/28");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

var apps = make_list(
  'Access',
  'Excel',
  'PowerPoint',
  'Project',
  'Publisher',
  'Visio',
  'Word'
);

var count = 0;

foreach var installed_app (apps)
  if (get_kb_list('installed_sw/Microsoft '+ installed_app)) 
    count++;

if (count == 0 && report_paranoia < 2)
  exit(0, "There are no Microsoft Office applications installed. However, in some edge cases, the " +
          "registry settings that allow the execution of untrusted macros may still be present and " +
          "enabled. To check if they are present, 'Report paranoia' must be set to 'Paranoid'."
);

var office_vers = make_list(
  '14.0',
  '15.0',
  '16.0'
);

#For Reporting
var office_disp  = {
  '14.0': 'Microsoft Office 2010',
  '15.0': 'Microsoft Office 2013',
  '16.0': 'Microsoft Office 2016'
};

var report = '';
registry_init();
var hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
var hku_list = get_registry_subkeys(handle:hku, key:'');

foreach var user (hku_list)
{
  var username = NULL;
  foreach var app (apps)
  {
    foreach var ver (office_vers)
    {
      var gpo_value_item = user + '\\' + 'Software\\Policies\\Microsoft\\Office\\' + 
                           ver + '\\' + app + '\\Security\\VBAWarnings';
      var gpo_value = get_registry_value(handle:hku, item:gpo_value_item);
        
      var value_item = user + '\\' + 'Software\\Microsoft\\Office\\' + ver + '\\' + 
                       app + '\\Security\\VBAWarnings';
      var value = get_registry_value(handle:hku, item:value_item);
      
      if (gpo_value == 1 || (isnull(gpo_value) && value == 1))
      {
        if (gpo_value == 1)
          report += 'Registry Key    : HKEY_USERS\\' + gpo_value_item + '\n';
        else
          report += 'Registry Key    : HKEY_USERS\\' + value_item + '\n';
        
        report += 'SID             : ' + user + '\n';
        username = get_hku_usernames(handle:hku, sid:user);
        if (!empty_or_null(username))
        {
          report += 'Username        : ' + username + '\n';
        }
        report += 'This application: ' + app + ' in ' + office_disp[ver] + 
          ' has untrusted macro execution enabled\n';
      }
    }
  }
}
RegCloseKey(handle:hku);
close_registry();

if (empty(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
