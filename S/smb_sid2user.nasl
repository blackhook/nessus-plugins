#
# (C) Tenable Network Security, Inc.
#
# @PREFERENCES@

include("compat.inc");

if (description)
{
 script_id(10399);
 script_version("1.82");
 script_cvs_date("Date: 2020/01/07");

 script_name(english:"SMB Use Domain SID to Enumerate Users");
 script_summary(english:"Enumerates users.");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate domain users.");
 script_set_attribute(attribute:"description", value:
"Using the domain security identifier (SID), Nessus was able to
enumerate the domain users on the remote Windows system.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : User management");

 script_copyright(english:"This script is Copyright (C) 2000-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies(
  "netbios_name_get.nasl",
  "smb_login.nasl",
  "smb_dom2sid.nasl"
 );
 script_require_keys(
  "SMB/transport",
  "SMB/name",
  "SMB/login",
  "SMB/password",
  "SMB/domain_sid"
 );
 script_require_ports(139, 445);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

plugin_selected = get_preference("SMB User Enumeration[checkbox]:RID");
if(plugin_selected == "no")
  exit(0, "This plugin has been disabled by scan policy preference.");

default_accounts = make_nested_array(
# rid                    display name                   specific kb item
  500, make_array('Name','Administrator account', 'KB','SMB/AdminName'),
  501, make_array('Name','Guest account',         'KB','SMB/GuestAccount'),
  502, make_array('Name','Kerberos account',      'KB','')
);

#---------------------------------------------------------#
# call LsaLookupSid with only one sid			  #
#---------------------------------------------------------#

function lookup_sid (handle, sid, rid)
{
 local_var fsid, psid, name, type, user, names, tmp;

 fsid = sid[0] + raw_byte (b: ord(sid[1])+1) + substr(sid,2,strlen(sid)-1) + raw_dword (d:rid);

 psid = NULL;
 psid[0] = fsid;

 names = LsaLookupSid (handle:handle, sid_array:psid);
 if (isnull(names))
   return NULL;

 name = names[0];
 # type, domain, user
 return  parse_lsalookupsid (data:name);
}

function report_user(name, rid, count, kb, extra)
{
  report += '  - ' + data_protection::sanitize_user_enum(users:name) + ' (id ' + rid;
  if (!empty_or_null(extra)) report += ', ' + extra;
  report += ')\n';
  replace_kb_item(name:"SMB/Users/" + count, value:name);
  if (!empty_or_null(default_accounts[rid]) && !empty_or_null(default_accounts[rid]['KB']))
    replace_kb_item(name:default_accounts[rid]['KB'], value:name);
}


port = kb_smb_transport();
if(!port)port = 139;
if(!get_port_state(port)) exit(0);

if(get_kb_item("TESTING_domain_sid_prefs"))
{
  __start_uid = get_kb_item('TESTING_domain_start_uid');
  __end_uid = get_kb_item('TESTING_domain_end_uid');
}
else
{
  __start_uid = int(get_preference("SMB Use Domain SID to Enumerate Users[entry]:Start UID :"));
  __end_uid   = int(get_preference("SMB Use Domain SID to Enumerate Users[entry]:End UID :"));
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

set_kb_item(name:"SMB/dom_users/start_uid", value: __start_uid);
set_kb_item(name:"SMB/dom_users/end_uid", value: __end_uid);

__no_enum = string(get_kb_item("SMB/Users/0"));
if(__no_enum) exit(0);

__no_enum = string(get_kb_item("SMB/Users/1"));
if(__no_enum) exit(0);

report = NULL;

login = kb_smb_login();
pass  = kb_smb_password();
if(!login)login = "";
if(!pass)pass = "";

domain = kb_smb_domain();

# we need the SID of the domain
sid = get_kb_item_or_exit("SMB/domain_sid");

sid = hex2raw(s:sid);

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

ret = NetUseAdd (login:login, password:pass, domain:domain, share:"IPC$");
if ( ret != 1 ) audit(AUDIT_SHARE_FAIL, 'IPC$');

handle = LsaOpenPolicy (desired_access:0x20801);
if (isnull(handle))
{
  NetUseDel();
  audit(AUDIT_FN_FAIL, 'LsaOpenPolicy');
}

# enumerate users

num_users = 0;
replace_kb_item(name:"SMB/Users/enumerated", value:TRUE);

foreach rid (keys(default_accounts))
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
    report_user(name:name,rid:mycounter,count:num_users);
  }
}


LsaClose (handle:handle);
NetUseDel ();

if(num_users > 0)
{
 replace_kb_item(name:"SMB/Users/count", value:num_users);
 report = '\n' + report + '\n' +
  'Note that, in addition to the Administrator, Guest, and Kerberos\n' +
  'accounts, Nessus has enumerated domain users with IDs between\n' +
  __start_uid + " and " + __end_uid + '. To use a different range, edit the scan policy\n' +
  "and change the 'Enumerate Domain Users: Start UID' and/or 'End UID'" + '\n' +
  "preferences under 'Assessment->Windows' and re-run the scan.  Only" + '\n' +
  'UIDs between 1 and 2147483647 are allowed for this range.\n';

 security_note(extra:report, port:port);
}
