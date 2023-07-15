#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11457);
 script_version("1.17");
 script_cvs_date("Date: 2018/06/05 14:13:35");

 script_name(english:"Microsoft Windows SMB Registry : Winlogon Cached Password Weakness");
 script_summary(english:"Determines the value of a remote key.");

 script_set_attribute(attribute:"synopsis", value:
"User credentials are stored in memory.");
 script_set_attribute(attribute:"description", value:
"The registry key 'HKLM\Software\Microsoft\WindowsNT\CurrentVersion\
Winlogon\CachedLogonsCount' is not 0. Using a value greater than 0 for
the CachedLogonsCount key indicates that the remote Windows host
locally caches the passwords of the users when they login, in order to
continue to allow the users to login in the case of the failure of the
primary domain controller (PDC).

Cached logon credentials could be accessed by an attacker and subjected  
to brute force attacks.");
 # https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-number-of-previous-logons-to-cache-in-case-domain-controller-is-not-available
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?184d3eab");
 # https://support.microsoft.com/en-us/help/172931/cached-domain-logon-information
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe16cea8");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/cc957390.aspx");
 script_set_attribute(attribute:"solution", value:
"Consult Microsoft documentation and best practices.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/24");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);

 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
 NetUseDel();
 audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 audit(AUDIT_REG_FAIL);
}

value = "";
key = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
item = "CachedLogonsCount";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel ();

if (!empty_or_null(value) && (value[1] != 0))
{
  report =
    '\n  Max cached logons : ' + value[1] + '\n'; 
  security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
}

