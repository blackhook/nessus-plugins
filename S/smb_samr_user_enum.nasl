
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126527);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/20");

  script_name(english:"Microsoft Windows SAM user enumeration");
  script_summary(english:"Enumerates users from the Security Accounts Manager");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate domain users from the local SAM.");
  script_set_attribute(attribute:"description", value:
"Using the domain security identifier (SID), Nessus was able to
enumerate the domain users on the remote Windows system using
the Security Accounts Manager.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Windows : User management");
  script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
  script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  script_require_ports (139, 445);
  exit(0);
}

include("agent.inc");
include("kerberos_func.inc");
include("smb_func.inc");

function get_plugin_preference()
{
  local_var testing = get_kb_item("TESTING_smb_samr_user_enum");
  if(!isnull(testing)) return "yes";
  return get_preference("SMB User Enumeration[checkbox]:SAMR");
}

if(agent()) exit(0,"This plugin is disabled on Nessus Agents.");

plugin_selected = get_plugin_preference();

if(plugin_selected == "no" || plugin_selected != "yes")
  exit(0, "This plugin has been disabled by scan policy preference.");

default_accounts = make_nested_array(
# rid                    display name                   specific kb item
  500, make_array('Name','Administrator account', 'KB','SMB/AdminName'),
  501, make_array('Name','Guest account',         'KB','SMB/GuestAccount'),
  502, make_array('Name','Kerberos account',      'KB','')
);

login = kb_smb_login();
pass = kb_smb_password();
domain  = kb_smb_domain();
port = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) audit(AUDIT_SHARE_FAIL, 'IPC$');

var info = NetGetSamrUsers();
NetUseDel();
# Grab the HKU registry subkeys to determine the Machine ID for creating local SIDs later
registry_init();
var hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
var subkeys = get_registry_subkeys(handle:hku, key:'');
RegCloseKey(handle:hku);
close_registry();
var machine_id = '';
foreach var key (subkeys)
{
  if (key =~ "^S-1-5-21-" && key !~ "_classes$")
  {
    sid_parts = split(key, sep:'-', keep:FALSE);
    for (var i=0; i<len(sid_parts)-2; i++)
    {
      if (empty_or_null(machine_id))
        machine_id = sid_parts[i] + '-';
      else
        machine_id = machine_id + sid_parts[i] + '-';
    }
    break;
  }
}

report = '';
if(!isnull(info))
{
  replace_kb_item(name:"SMB/Users/enumerated", value:TRUE);
  count = 0;
  foreach user(info["names"])
  {
    count += 1;

    rid = user["rid"];
    name = user["name"];

    if(isnull(rid) || isnull(name))
      continue;

    if(!empty_or_null(default_accounts[rid]))
    {
      if(empty_or_null(user["full_name"]))
          user["full_name"] = default_accounts[rid]["Name"];
      else if(empty_or_null(user["desc"]))
          user["desc"] = default_accounts[rid]["Name"];

      if(!empty_or_null(default_accounts[rid]['KB']))
        replace_kb_item(name:default_accounts[rid]['KB'], value:name);
    }

    if ('-' >!< rid)
      rid = machine_id + rid;
    report += '  - ' + data_protection::sanitize_user_enum(users:name) + ' (id ' + rid;
    if(!empty_or_null(user["full_name"]))
      report += ', ' + user["full_name"];
    if(!empty_or_null(user["desc"]))
      report += ', ' + user["desc"];
    report += ')\n';
    replace_kb_item(name:"SMB/Users/" + count, value:name);
  }

  replace_kb_item(name:"SMB/Users/count", value:count);
  security_note(port:0, extra:report);
}
