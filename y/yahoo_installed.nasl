#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(11432);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_name(english:"Yahoo! Messenger Detection");
  script_summary(english:"Detects Yahoo! Messenger");

 script_set_attribute(attribute:"synopsis", value:"The remote Windows host contains an instant-messaging application.");
 script_set_attribute(attribute:"description", value:
"Yahoo! Messenger, an instant-messaging application, is installed on
the Windows host.");
 script_set_attribute(attribute:"see_also", value:"https://help.yahoo.com/kb/SLN28776.html?redirect=true");
 script_set_attribute(attribute:"solution", value:
"Make sure the use of this program is in accordance with your corporate
security policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/21");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:yahoo:yahoo_ybox");
script_set_attribute(attribute:"asset_inventory", value:"True");
script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
script_set_attribute(attribute:"agent", value:"windows");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2003-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);



include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Yahoo! Messenger";

# Unless we're being paranoid, do a quick check for the install.
if (report_paranoia < 2)
{
  key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Yahoo! Messenger/DisplayName";
  if (!get_kb_item(key)) exit(0);
}


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Classes\ymsgr\shell\open\command";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value))
  {
    exe = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:value[1]);
    path = ereg_replace(pattern:"^(.+)\\Y(ahooMessenger|Pager)\.exe$", replace:"\1", string:exe, icase:TRUE);
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
exe2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe2,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}


# Clean up.
NetUseDel();


# Update KB and report findings.
if (!isnull(ver))
{
  version = ver[0] +  "." +  ver[1] +  "." +  ver[2] +  "." +  ver[3];

  set_kb_item(name:"SMB/Yahoo/Messenger/Path", value:path);
  set_kb_item(name:"SMB/Yahoo/Messenger/Version", value:version);

  register_install(
    vendor:"Yahoo",
    product:"Messenger",
    app_name:app,
    path:path,
    version:version,
    cpe: "cpe:/a:yahoo:yahoo_ybox");

  report_installs(app_name:app, port:port);
}
