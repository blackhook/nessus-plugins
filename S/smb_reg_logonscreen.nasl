#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');

if (description)
{
 script_id(11460);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/31");

 script_name(english:"Microsoft Windows SMB Registry : Classic Logon Screen");

 script_set_attribute(attribute:"synopsis", value:"User lists is displayed locally.");
 script_set_attribute(attribute:"description", value:
"The registry key HKLM\Software\Microsoft\Windows
NT\CurrentVersion\WinLogon\LogonType is set to 1.

It means that users who attempt to log in locally will see get the
'new' WindowsXP logon screen which displays the list of users of the
remote host.");
 script_set_attribute(attribute:"solution", value:"Use regedt32 and set the value of this key to 0");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:'cvss_score_rationale', value:"Score based on an in-depth analysis by Tenable.");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/24");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl",
		     "smb_reg_service_pack_XP.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access", "SMB/ProductName");
 script_require_ports(139, 445);
 exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('smb_func.inc');

# Ensure host is running windows
var productname = get_kb_item_or_exit('SMB/ProductName');
if ("windows" >!< tolower(productname)) audit(AUDIT_OS_NOT, 'Windows');

# Checking registry access
if (!get_kb_item('SMB/registry_access')) exit(1, 'SMB/registry_access KB item is missing.');

var login	= kb_smb_login();
var pass	= kb_smb_password();
var domain  = kb_smb_domain();
var port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

var r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
 NetUseDel();
 audit(AUDIT_SHARE_FAIL, "IPC$");
}

var hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 audit(AUDIT_REG_FAIL);
}

var key = "Software\Microsoft\Windows NT\CurrentVersion\WinLogon";
var item = "LogonType";

var key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 var report = '';
 var value = RegQueryValue(handle:key_h, item:item);

if (!isnull (value) && (value[1] != 0))
 {
   var report ='The registry key HKLM\\Software\\Microsoft\\WindowsNT\\CurrentVersion\\WinLogon\\LogonType is set to 1.\n';
   security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
   RegCloseKey (handle:key_h);
 }
 else
 {
   RegCloseKey (handle:hklm);
   NetUseDel ();
   audit(AUDIT_HOST_NOT, 'affected');
 }
}