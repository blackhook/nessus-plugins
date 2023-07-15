#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92369);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/06");

  script_name(english:"Microsoft Windows Time Zone Information");
  script_summary(english:"Report time zone information.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to collect and report time zone information from the
remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to collect time zone information from the remote
Windows host and generate a report as a CSV attachment.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("data_protection.inc");

# Disable if GDPR is set
data_protection::disable_plugin_if_set();

function display_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return tmp + toupper(hexstr(raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )));
}

get_kb_item_or_exit("SMB/Registry/Enumerated");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

if (isnull(hklm))
{
   close_registry();
   audit(AUDIT_REG_FAIL);
}

#HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation
# REG_SZ
# DaylightName
# StandardName
# TimeZoneKeyName
# REG_DWORD
# ActiveTimeBias
# Bias
# DaylightBias
# DynamicDaylightTimeDisabled
# StandardBias
# REG_BINARY
# DaylightStart
# StandardStart
# get_registry_values(handle, items)
key_path = 'SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation\\';

string_values = get_registry_values(handle:hklm, items:make_list(key_path + "DaylightName", key_path + "StandardName", key_path + "TimeZoneKeyName"));

dword_values = get_registry_values(handle:hklm, items:make_list(key_path + "ActiveTimeBias", key_path + "Bias", key_path + "DaylightBias", key_path + "DynamicDaylightTimeDisabled", key_path + "StandardBias"));

binary_values = get_registry_values(handle:hklm, items:make_list(key_path + "DaylightStart", key_path + "StandardStart"));

RegCloseKey(handle:hklm);

close_registry();

report = '';
timezone_data = make_list();
foreach key(keys(string_values))
{
  report += 'HKLM\\' + key + ' : ' + string_values[key] + '\n';
}

foreach key(keys(dword_values))
{
  report += 'HKLM\\' + key + ' : ' + display_dword(dword:dword_values[key]) + '\n';
}

foreach key(keys(binary_values))
{
  report += 'HKLM\\' + key + ' : ' + hexstr(binary_values[key]) + '\n';
}

if (strlen(report) > 0)
{
  security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
}
else
{
  exit(0, "No time zone information found.");
}
