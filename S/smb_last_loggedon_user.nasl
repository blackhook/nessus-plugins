#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38689);
  script_version("1.12");
  script_cvs_date("Date: 2019/09/02  7:31:05");

  script_name(english:"Microsoft Windows SMB Last Logged On User Disclosure");
  script_summary(english:"Checks the last logged on user.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to identify the last logged on user on the remote
host.");
  script_set_attribute(attribute:"description", value:
"By connecting to the remote host with the supplied credentials, Nessus
was able to identify the username associated with the last successful
logon.

Microsoft documentation notes that interactive console logons change the 
DefaultUserName registry entry to be the last logged-on user.");
  # https://support.microsoft.com/en-us/help/324737/how-to-turn-on-automatic-logon-in-windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a29751b5");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('misc_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('data_protection.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
os = get_kb_item_or_exit('SMB/WindowsVersion');

key = 'Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI';
key_name = 'LastLoggedOnUser';

# If OS is Windows 2003/XP or earlier we overwrite the registry keys we search for
if ('3.' >< os || '4.' >< os || '5.' >< os)
{
  key = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon';
  key_name = 'DefaultUsername';
}

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1) {
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,'IPC$');
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

username = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  # value = RegQueryValue(handle:key_h, item:'DefaultUserName');
  value = RegQueryValue(handle:key_h, item:key_name);
  if (!isnull(value)) username = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();

if(!empty_or_null(username))
{
  report = NULL;
  report = '\nLast Successful logon : ' + data_protection::sanitize_user_enum(users:username) + '\n';
  set_kb_item(name:'SMB/last_user_login', value:username);
  security_report_v4(severity:SECURITY_NOTE, port:port,extra:report);
}
