#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(160511);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/28");

  script_name(english:"Fetch the HKLM\SAM registry data");
  script_summary(english:"Fetch the HKLM\SAM registry data");

  script_set_attribute(attribute:"synopsis", value:"Fetch the HKLM\SAM registry data");
  script_set_attribute(attribute:"description", value:"Fetch the HKLM\SAM registry data");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"user_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate therof");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_reg_query.inc");
include('nessusd_product_info.inc');
include('http.inc');
include('json2.inc');

function get_sid_segment(sid_chunk)
{
  local_var segment;
  local_var idx;

  for (idx=0; idx < 8; idx +=2)
    segment = substr(sid_chunk, idx, idx+1) + segment;

  return uint(hex2dec(xvalue:segment));
}


if (!nessusd_is_agent())
{
  exit(0, 'This plugin only runs on Nessus Agents');
}

registry_init();
var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Get the machine SID by reading in the registry value from SAM\SAM\Domains\Account\V
# The last 12 hex values (24 characters) in that string give us the machine sid
# Break the final 12 hex values into 3 segments of 4 hex values
# For each segment, reverse the order of hex numbers
# Convert the hex number into an unsigned integer to get that section of the machine sid
# Combine the segments together with a '-' separator to get the machine sid
var i;
var machine_sid = make_list();
var v = get_registry_value(handle:hklm, item:"SAM\SAM\Domains\Account\V");
if (!empty_or_null(v))
{
  var hexv = hexstr(v);
  var sid_segment = substr(hexv, strlen(hexv)-24, strlen(hexv)-1);
  for (i = 0; i < 3; i++)
  {
    segment_start = i*8;
    segment_end = (i*8) + 7;

    machine_sid[i] = get_sid_segment(sid_chunk:substr(sid_segment, segment_start, segment_end));
  }
  machine_id_str = 'S-1-5-21-' + join(machine_sid, sep:'-') + '-';
}
else
  machine_id_str = '';

var report = 'Users :\n';
subkeys = get_registry_subkeys(handle:hklm, key:"SAM\SAM\Domains\Account\Users\Names");
var users = {};
foreach var user (subkeys)
{
  user_reg_str = "SAM\SAM\Domains\Account\Users\Names\" + user + "\";
  key_h = RegOpenKey(handle:hklm, key:user_reg_str, mode:MAXIMUM_ALLOWED);
  item = RegEnumValue(handle:key_h, index:0);
  RegCloseKey(handle:key_h);
  if (empty_or_null(item))
    continue;

  user_id = item[0];
  
  users[machine_id_str + user_id] = {
    name: user
  };
  report += '  - ' + user + ' (' + machine_id_str + user_id + ')\n';
}

report += 'Groups :\n';
subkeys = get_registry_subkeys(handle:hklm, key:"SAM\SAM\Domains\Account\Groups\Names");
var groups = {};
foreach var group (subkeys)
{
  group_reg_str = "SAM\SAM\Domains\Account\Groups\Names\" + group + "\";
  key_h = RegOpenKey(handle:hklm, key:user_reg_str, mode:MAXIMUM_ALLOWED);
  item = RegEnumValue(handle:key_h, index:0);
  RegCloseKey(handle:key_h);
  if (empty_or_null(item))
    continue;
  
  group_id = item[0];

  groups[machine_id_str + group_id] = {
    name: group
  };
  report += '  - ' + group + ' (' + machine_id_str + group_id + ')\n';;
}
RegCloseKey(handle:hklm);
close_registry();

set_kb_item(name:'SMB/Registry/SAM/Users', value:json_write(users));
set_kb_item(name:'SMB/Registry/SAM/Groups', value:json_write(groups));

port = kb_smb_transport();
if (!port) port = 445;
security_note(port:port, extra:report);
