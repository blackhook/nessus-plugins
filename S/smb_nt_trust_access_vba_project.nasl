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
  script_id(123461);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_name(english:"Microsoft Office Trust Access to VBA Project Model Object Enabled");

  script_set_attribute(attribute:"synopsis", value:
"A Microsoft Office application installed on the remote host has trust
access to VBA project model object enabled.");
  script_set_attribute(attribute:"description", value:
"A Microsoft Office application installed on the remote host has trust
access to VBA project model object enabled.");

  script_set_attribute(attribute:"solution", value:
"Disable the trust access to VBA project model object.");
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
include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');

var apps = make_list(
  'Excel',
  'PowerPoint',
  'Project',
  'Visio',
  'Word'
);

var office_vers = make_list(
  '14.0',
  '15.0',
  '16.0'
);

#For Reporting
var office_disp  = {
  '14.0': 'Microsoft Office 2014',
  '15.0': 'Microsoft Office 2015',
  '16.0': 'Microsoft Office 2016'
};

var prefix = 'Software\\Microsoft\\Office\\';
var vbom_key = '\\Security\\AccessVBOM';

var report = '';
registry_init();
var hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
var hku_list = get_registry_subkeys(handle:hku, key:'');

var user, username, app, ver, item, value;
foreach var user (hku_list)
{
  username = NULL;
  foreach var app (apps)
  {
    foreach var ver (office_vers)
    {
      item = user + '\\' + prefix + ver + '\\' + app + vbom_key;
      value = get_registry_value(handle:hku,
        item:item);
      if (value == 1)
      {       
        report += 'SID          : ' + user + '\n';
        username = get_hku_usernames(handle:hku, sid:user);
        if (!empty_or_null(username))
        {
          report += 'Username     : ' + username + '\n';
        }
        report += 'Registry Key : HKU\\'+ item + ' = ' + value + '\n\n'; 
        report += 'The ' + app + ' application in ' + office_disp[ver] +
          ' has trust access to VBA project model object enabled.\n';
      }
    }
  }
}
RegCloseKey(handle:hku);
close_registry();

if (empty(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
