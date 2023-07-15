#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10398);
 script_version("1.57");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/28");

 script_name(english:"Microsoft Windows SMB LsaQueryInformationPolicy Function NULL Session Domain SID Enumeration");
 script_summary(english:"Gets the domain SID.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the domain SID.");
 script_set_attribute(attribute:"description", value:
"By emulating the call to LsaQueryInformationPolicy(), it was possible
to obtain the domain SID (Security Identifier).

The domain SID can then be used to get the list of users of the
domain.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2000-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("smb_scope.nasl", "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/test_domain");
 script_require_ports(139, 445);

 exit(0);
}

include("smb_func.inc");
include("spad_log_func.inc");

d = get_kb_item("SMB/test_domain");
if(! d)
  exit(0, 'The scan policy is not configured to request domain information. ' +
          'Please see Preferences/SMB Scope.');

port = kb_smb_transport();
if(!port)port = 445;

login = kb_smb_login();
pass  = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";

dom = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if ( ret != 1 ) audit(AUDIT_SHARE_FAIL, 'IPC$');

handle = LsaOpenPolicy (desired_access:0x20801);
if (isnull(handle))
{
  NetUseDel ();
  audit(AUDIT_FN_FAIL, 'LsaOpenPolicy');
}

ret = LsaQueryInformationPolicy (handle:handle, level:PolicyPrimaryDomainInformation);
if (isnull (ret))
{
 LsaClose (handle:handle);
 NetUseDel ();
 audit(AUDIT_FN_FAIL, 'LsaQueryInformationPolicy');
}

sid = ret[1];
primary_domain = ret[0];

LsaClose (handle:handle);
NetUseDel ();

if(primary_domain)
{
  prev_domain = get_kb_item("SMB/primary_domain");
  if (!empty_or_null(prev_domain))
  {
    spad_log(message:'SMB/primary_domain previously determined as ' + prev_domain);
    if (prev_domain != primary_domain)
    {
      spad_log(message:"CONFLICT - domain determined by microsoft_windows_nbt_info.nasl: " + prev_domain);
      spad_log(message:"CONFLICT - domain determined by smb_dom2sid.nasl               : " + primary_domain);
    }
  }
  else
  {
    spad_log(message:'Setting Netbios SMB/primary_domain as ' + primary_domain);
    set_kb_item(name:"SMB/netbios_domain_plugin_source", value:'smb_dom2sid.nasl');
  }

  set_kb_item(name:"SMB/primary_domain", value:primary_domain);
}

if(strlen(sid) != 0)
{
 set_kb_item(name:"SMB/domain_sid", value:hexstr(sid));

 report = strcat("The remote domain SID value is :\n", sid2string(sid:sid));

 security_note(extra:report, port:port);
}
else exit(0, 'Failed to obtain domain SID, remote host may not be a domain member.');
