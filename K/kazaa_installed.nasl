#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11426);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Kazaa on Windows Detection");
  script_summary(english:"Checks for Kazaa on Windows");

 script_set_attribute(attribute:"synopsis", value:
"There is a peer-to-peer file sharing application on the remote Windows
host.");
 script_set_attribute(attribute:"description", value:
"Kazaa, a peer-to-peer file sharing application is installed on the
remote host.");
 script_set_attribute(attribute:"see_also", value:"http://www.kazaa.com/");
 script_set_attribute(attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"agent", value:"windows");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/21");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:kazaa:kazaa_media_desktop");
script_set_attribute(attribute:"asset_inventory", value:"True");
script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2003-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Kazaa on Windows";

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Detect which registry key Kazaa's install used.
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod =~ "^Kazaa($| [0-9])")
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}


# Connect to the appropriate share.
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


# Determine where it's installed.
path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}

# Check for legacy Kazaa version
if (isnull(path))
{
  key = "SOFTWARE\KAZAA\CloudLoad";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"ExeDir");
    if (!isnull(item))
    {
      path = item[1];
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
    }

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine its version from the executable itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\kazaa.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

version = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  if (isnull(ver)) version = "unknown";
  else version = ver[0] +  "." +  ver[1] +  "." +  ver[2] +  "." +  ver[3];

  CloseFile(handle:fh);
}
NetUseDel();


# Save and report the version number and installation path.
if (!isnull(version))
{
  kb_base = "SMB/Kazaa";
  set_kb_item(name:kb_base+"/Path", value:path);
  set_kb_item(name:kb_base+"/Version", value:version);
  register_install(
    vendor:"Kazaa",
    product:"Kazaa Media Desktop",
    app_name:app,
    path:path,
    version:version,
    cpe: "cpe:/a:kazaa:kazaa_media_desktop");

  report_installs(app_name:app, port:port);
}
