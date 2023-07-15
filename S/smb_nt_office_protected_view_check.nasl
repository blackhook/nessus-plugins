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
  script_id(123460);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/09");

  script_name(english:"Microsoft Office Protected View Disabled");

  script_set_attribute(attribute:"synopsis", value:
"A Microsoft Office application installed on the remote host has protected
view disabled.");
  script_set_attribute(attribute:"description", value:
"A Microsoft Office application installed on the remote host has protected
view disabled.");

  script_set_attribute(attribute:"solution", value:
"Enable protected view settings.");
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

apps = make_list(
  'Excel',
  'PowerPoint',
  'Project',
  'Visio',
  'Word'
);

office_vers = make_list(
  '14.0',
  '15.0',
  '16.0'
);

#For Reporting
office_disp  = {
  # https://en.wikipedia.org/wiki/Microsoft_Office#History_of_releases
  '14.0': 'Microsoft Office 2010',
  '15.0': 'Microsoft Office 2013',
  '16.0': 'Microsoft Office 2016/2019'
};

prefix = 'Software\\Microsoft\\Office\\';
disable_internet_key = '\\Security\\ProtectedView\\DisableInternetFilesInPV';
disable_unsafe_key = '\\Security\\ProtectedView\\DisableUnsafeLocationsInPV';
disable_attachment_key = '\\Security\\ProtectedView\\DisableAttachmentsInPV';

report = '';
registry_init();
hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
hku_list = get_registry_subkeys(handle:hku, key:'');

foreach var user (hku_list)
{
  username = NULL;
  temp_report = '';
  foreach var app (apps)
  {
    foreach var ver (office_vers)
    {
      dik_item = user + '\\' + prefix + ver + '\\' + app + disable_internet_key;
      value = get_registry_value(handle:hku, item:dik_item);
      if (value == 1)
      {
        temp_report += 'Registry Key     : HKU\\' + dik_item + ' = ' + value + '\n';
        temp_report += 'This application : ' + app + ' in ' + office_disp[ver] + 
          ' has protected view from files originating from the internet disabled.\n';
      }

      duk_item = user + '\\' + prefix + ver + '\\' + app + disable_unsafe_key;
      value = get_registry_value(handle:hku, item:duk_item);
      if (value == 1)
      {
        temp_report += 'Registry Key     : HKU\\' + duk_item + ' = ' + value + '\n';
        temp_report += 'This application : ' + app + ' in ' + office_disp[ver] + 
          ' has protected view from files located from potentially unsafe locations disabled.\n';
      }

      dak_item = user + '\\' + prefix + ver + '\\' + app + disable_attachment_key;
      value = get_registry_value(handle:hku, item:dak_item);
      if (value == 1)
      {
        temp_report += 'Registry Key     : HKU\\' + dak_item + ' = ' + value + '\n';
        temp_report += 'This application : ' + app + ' in ' + office_disp[ver] + 
          ' has protected view for Outlook attachments disabled.\n';
      }
    }
  }
  if (!empty_or_null(temp_report))
  {
    report += 'SID              : ' + user + '\n';
    username = get_hku_usernames(handle:hku, sid:user);
    if (!empty_or_null(username)) {
      report += 'Username         : ' + username + '\n';
    }
    report += temp_report;
  }
}
RegCloseKey(handle:hku);
close_registry();

if (empty(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
