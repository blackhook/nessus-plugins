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
  script_id(123458);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/27");

  script_name(english:"Microsoft Office ActiveX Controls Enabled Without Restrictions Or Prompting");
  script_summary(english:"Checks the trust center settings of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"A Microsoft Office application installed on the remote host has ActiveX
controls enabled without restrictions and without prompting.");
  script_set_attribute(attribute:"description", value:
"A Microsoft Office application installed on the remote host has ActiveX
controls enabled without restrictions and without prompting.");

  script_set_attribute(attribute:"solution", value:
"Disable ActiveX controls or enable them with prompt and with additional restrictions.");
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

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

function override_regkey(handle, user, base_key, override_key) {
  var ret;
  dbg::detailed_log(lvl: 2, msg: 'Examining registry keys for user: ' + obj_rep(user));
  ret = get_registry_value(handle:handle, item:user + '\\' + override_key);
  dbg::detailed_log(lvl: 2, msg: 'Override registry key: "' + override_key + '" returned ' + obj_rep(ret));
  if(!empty_or_null(ret))
    return ret;
  ret = get_registry_value(handle:handle, item:user + '\\' + base_key);
  dbg::detailed_log(lvl: 2, msg: 'Basic registry key: "' + override_key + '" was used and returned ' + obj_rep(ret));
  return ret;
}

var disable_activex_key = 'Software\\Microsoft\\Office\\Common\\Security\\DisableAllActiveX';
var ufi_controls_key = 'Software\\Microsoft\\Office\\Common\\Security\\UFIControls';

var override_disable_activex_key = 'Software\\Policies\\Microsoft\\Office\\Common\\Security\\DisableAllActiveX';
var override_ufi_controls_key = 'Software\\Policies\\Microsoft\\Office\\Common\\Security\\UFIControls';

var report = '';
var username, value;
registry_init();
var hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
var hku_list = get_registry_subkeys(handle:hku, key:'');

foreach var user (hku_list)
{
  username = NULL;
  value = override_regkey(handle: hku, user: user, base_key: disable_activex_key, override_key: override_disable_activex_key);
  if (value != 1)
  {
    value = override_regkey(handle: hku, user: user, base_key: ufi_controls_key, override_key: override_ufi_controls_key);
    if (value == 1)
    {
      report += 'SID: ' + user + '\n';
      username = get_hku_usernames(handle:hku, sid:user);
      if (!empty_or_null(username))
      {
        report += 'Username: ' + username + '\n';
      }
      report += 'The Microsoft Office installed on this machine for this user has' +
        ' ActiveX Controls enabled without restrictions and without prompting.\n';
    }
  }
}
RegCloseKey(handle:hku);
close_registry();

if (empty(report))
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);

