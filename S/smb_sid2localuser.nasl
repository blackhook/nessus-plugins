#
# (C) Tenable Network Security, Inc.
#
# @PREFERENCES@

include("compat.inc");

if (description)
{
 script_id(10860);
 script_version("1.62");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/28");


 script_name(english:"SMB Use Host SID to Enumerate Local Users");
 script_summary(english:"Enumerates local users.");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate local users.");
 script_set_attribute(attribute:"description", value:
"Using the host security identifier (SID), Nessus was able to enumerate
local users on the remote Windows system.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/02/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"asset_inventory_category", value:"user_enumeration");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : User management");

 script_copyright(english:"This script is Copyright (C) 2002-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("smb_host2sid.nasl");
 script_require_keys(
  "SMB/transport",
  "SMB/name",
  "SMB/login",
  "SMB/password",
  "SMB/host_sid"
 );
 script_require_ports(139, 445);

 exit(0);
}

include("smb_func.inc");
include('json2.inc');

plugin_selected = get_preference("SMB User Enumeration[checkbox]:RID");

if(plugin_selected == "no")
  exit(0, "This plugin has been disabled by scan policy preference.");

default_accounts = make_nested_array(
# rid                    display name                   specific kb item
  500, make_array('Name','Administrator account', 'KB','SMB/LocalAdminName'),
  501, make_array('Name','Guest account',         'KB','SMB/LocalGuestAccount'),
  502, make_array('Name','Kerberos account',      'KB','')
);

#---------------------------------------------------------#
# call LsaLookupSid with only one sid			  #
#---------------------------------------------------------#

function lookup_sid (handle, sid, rid)
{
 local_var fsid, psid, name, type, user, names, tmp;

 if ( isnull(sid[1]) )
   return NULL;

 fsid = sid[0] + raw_byte (b: ord(sid[1])+1) + substr(sid,2,strlen(sid)-1) + raw_dword (d:rid);

 psid = NULL;
 psid[0] = fsid;

 names = LsaLookupSid (handle:handle, sid_array:psid);
 if (isnull(names))
   return NULL;

 name = names[0];

 # type, domain, user
 return parse_lsalookupsid (data:name);
}

function report_user(name, rid, sid, count, kb, extra)
{
  report += '  - ' + data_protection::sanitize_user_enum(users:name) + ' (id ' + rid;
  if (!empty_or_null(extra)) report += ', ' + extra;
  report += ')\n';
  set_kb_item(name:"SMB/LocalUsers/" + count, value:name);
  set_kb_item(
    name:"SMB/LocalUsers/" + count + "/Info/SID", 
    value:"S-" + sid2string(sid:sid) + '-' + rid);
  if (!empty_or_null(default_accounts[rid]) && !empty_or_null(default_accounts[rid]['KB']))
    set_kb_item(name:default_accounts[rid]['KB'], value:name);
}

port = kb_smb_transport();
if(!port)port = 445;

if(get_kb_item("TESTING_local_sid_prefs"))
{
  __start_uid = get_kb_item('TESTING_local_start_uid');
  __end_uid = get_kb_item('TESTING_local_end_uid');
}
else
{
  __start_uid = int(get_preference("SMB Use Host SID to Enumerate Local Users[entry]:Start UID :"));
  __end_uid   = int(get_preference("SMB Use Host SID to Enumerate Local Users[entry]:End UID :"));
}

if(!__start_uid)__start_uid = 1000;
if(!__end_uid)__end_uid = __start_uid + 200;

if(__start_uid < 1) __start_uid = 1;
if(__end_uid < 1) __end_uid = 1;

if(__end_uid < __start_uid)
{
 t  = __end_uid;
 __end_uid = __start_uid;
 __start_uid = t;
}

set_kb_item(name:"SMB/local_users/start_uid", value: __start_uid);
set_kb_item(name:"SMB/local_users/end_uid", value: __end_uid);


__no_enum = string(get_kb_item("SMB/LocalUsers/0"));
if(__no_enum)exit(0);

__no_enum = string(get_kb_item("SMB/LocalUsers/1"));
if(__no_enum)exit(0);


login = kb_smb_login();
pass  = kb_smb_password();
if(!login)login = "";
if(!pass)pass = "";

domain = kb_smb_domain();

# we need the SID of the domain
sid = get_kb_item_or_exit("SMB/host_sid");

sid = hex2raw(s:sid);

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

ret = NetUseAdd (login:login, password:pass, domain:domain, share:"IPC$");
if ( ret != 1 ) audit(AUDIT_SHARE_FAIL, 'IPC$');

handle = LsaOpenPolicy (desired_access:0x20801);
if (isnull(handle))
{
  NetUseDel ();
  audit(AUDIT_FN_FAIL, 'LsaOpenPolicy');
}

num_users = 0;
report = "";
set_kb_item(name:"SMB/LocalUsers/enumerated", value:TRUE);

# Report default accounts
foreach var rid (keys(default_accounts))
{
  res = lookup_sid(handle:handle, sid:sid, rid:rid);
  if (isnull(res)) continue;
  type = res[0];
  name = res[2];
  # type 1 user
  if(type == 1 && name)
  {
    num_users += 1;
    acct = default_accounts[rid];
    report_user(
      name:name,
      rid:rid,
      sid:sid,
      count:num_users,
      kb:acct['KB'],
      extra:acct['Name']
    );
  }
}

#
# Retrieve the name of the users between __start_uid and __end_uid
#
mycounter = __start_uid - 1;
# pre-increment
while(++mycounter <= __end_uid)
{
  if(!isnull(default_accounts[mycounter]))
    continue;
  res = lookup_sid(handle:handle, sid:sid, rid:mycounter);
  if (isnull(res)) continue;

  type = res[0];
  name = res[2];
  if(type == 1 && name)
  {
    num_users += 1;
    report_user(name:name,rid:mycounter,sid:sid,count:num_users);
  }
}

LsaClose (handle:handle);
NetUseDel ();

if(num_users > 0)
{
 set_kb_item(name:"SMB/LocalUsers/count", value:num_users);
 report = '\n' + report + '\n' +
  'Note that, in addition to the Administrator, Guest, and Kerberos\n' +
  'accounts, Nessus has enumerated local users with IDs between\n' +
  __start_uid + " and " + __end_uid + '. To use a different range, edit the scan policy\n' +
  "and change the 'Enumerate Local Users: Start UID' and/or 'End UID'" + '\n' +
  "preferences under 'Assessment->Windows' and re-run the scan. Only" + '\n' +
  'UIDs between 1 and 2147483647 are allowed for this range.\n';

 security_note(extra:report, port:port);
}
