#%NASL_MIN_LEVEL 7300
#
# (C) Tenable, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(161502);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_name(english:"Microsoft Windows Logged On Users");
  
  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to determine the logged on users from the registry");
  script_set_attribute(attribute:"description", value:
"Using the HKU registry, Nessus was able to enuemrate the SIDs of logged on users");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/25");
  
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_reg_query.inc");
include("data_protection.inc");

var user_sid, userdomain, username;

registry_init();
var hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
var subkeys = get_registry_subkeys(handle:hku, key:'');

var report = '';
foreach key (subkeys)
{
  if (key =~ "^S-1-5-21-" && key !~ "_classes$")
  {
    report += '  - ' + key + '\n';
    userdomain = get_registry_value(handle:hku, item:key + '\\Volatile Environment\\USERDOMAIN');
    report += '    Domain   : ' + userdomain + '\n';
    username = get_registry_value(handle:hku, item:key + '\\Volatile Environment\\USERNAME');
    report += '    Username : ' + data_protection::sanitize_user_enum(users:username) + '\n';
  }
}
RegCloseKey(handle:hku);
close_registry();

if (!empty_or_null(report))
  report = 'Logged on users :\n' + report;
port = kb_smb_transport();
if (!port) port = 445;
security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);