#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10412);
 script_version("1.36");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/16");

 script_xref(name:"MSKB", value:"324737");

 script_name(english:"Microsoft Windows SMB Registry : Autologon Enabled");
 script_summary(english:"Determines if the autologon feature is installed");

 script_set_attribute(attribute:"synopsis", value:"Anyone can logon to the remote system.");
 script_set_attribute(attribute:"description", value:
"This script determines whether the autologon feature is enabled. This
feature allows an intruder to log into the remote host as
DefaultUserName with the password DefaultPassword.");
 script_set_attribute(attribute:"solution", value:
"Delete the keys AutoAdminLogon and DefaultPassword under
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/315231");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/20");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl", "os_fingerprint.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

# Confirm that the Asset is a Windows Host
os = get_kb_item_or_exit('Host/OS');
if ('Windows' >!< os) audit(AUDIT_HOST_NOT, 'Windows');

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
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
report = '';

if (isnull(key_h)) {
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

username = RegQueryValue(handle:key_h, item:"DefaultUserName");
password = RegQueryValue(handle:key_h, item:"DefaultPassword");
autologon = RegQueryValue(handle:key_h, item:"AutoAdminLogon");

if ((!isnull(autologon) &&  (autologon[1] =~ "^[ \t]*0*[1-9]")) &&
    (!isnull (username) && (username[1] != "")) &&
     !isnull(password) ) {
  cleaned = substr(password[1],0,0)
          + crap(data:"*", 6)
          + substr(password[1], (strlen(password[1])-1));
  report = 'Autologon is enabled on this host.\n' +
        "This allows an attacker to access the domain: " + domain + " as " + username[1] + "/" + cleaned +
        '\n\nNote: The password displayed has been partially obfuscated.';
}

RegCloseKey (handle:key_h);
RegCloseKey (handle:hklm);
NetUseDel ();

if (report)
{
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
