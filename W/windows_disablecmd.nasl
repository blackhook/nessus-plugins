#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164690);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/05");

  script_name(english:"Windows Disabled Command Prompt Enumeration");

  script_set_attribute(attribute:"synopsis", value:
"This plugin determines if the DisableCMD policy is enabled or disabled on the
remote host for each local user.");
  script_set_attribute(attribute:"description", value:
"The remote host may employ the DisableCMD policy on a per user basis. Enumerated local 
 users may have the following registry key:
 'HKLM\Software\Policies\Microsoft\Windows\System\DisableCMD'

  - Unset or 0: The command prompt is enabled normally.
  - 1: The command promt is disabled.
  - 2: The command prompt is disabled however windows batch processing is allowed.");
  # https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-shellcommandpromptregedittools#admx-shellcommandpromptregedittools-disablecmd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b40698bc");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_local_users.nbin", 'smb_hotfixes.nasl');
  script_require_keys("WMI/LocalUsers/enumerated", "SMB/Registry/Enumerated");

  exit(0);
}

include('smb_hotfixes.inc');

var user_count, accounts_array, reg_values;
var username, sid, status, report;
var kb_prefix = 'WMI/LocalUsers/';

if (hotfix_check_sp_range(win2k:'0,4', xp:'0,3', win2003:'0,2', vista:'0,2', win7:'0,1', win8:'0', win81:'0', win10:'0') < 1)
  exit(0, 'The remote host does not support the DisableCMD policy.');

port = get_kb_item("SMB/transport");
if (isnull(port)) port = 445;

user_count = get_kb_item(kb_prefix + 'count');

for (var i=1; i<=user_count; i++)
{
  if (username = get_kb_item(kb_prefix + i))
  {
    if (sid = get_kb_item(kb_prefix + i + '/Info/SID'))
    {
      accounts_array[username]['SID'] = sid;
    }
  }
}

reg_values = get_hku_single_values(item:'\\Software\\Policies\\Microsoft\\Windows\\System\\DisableCMD', resolve_sid:FALSE);

foreach username (keys(accounts_array))
{
  accounts_array[username]['DisableCMD'] = reg_values[accounts_array[username]['SID']];
}

foreach username (keys(accounts_array))
{
  report += '\nUsername: ' + username;
  report += '\n  SID: ' + accounts_array[username]['SID'];
  if (empty_or_null(accounts_array[username]['DisableCMD']))
    report += '\n  DisableCMD: Unset\n';
  else
    report += '\n  DisableCMD: ' + accounts_array[username]['DisableCMD'] + '\n';
}

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);